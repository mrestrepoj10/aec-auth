import { createHmac } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import type { TokenRequest, TokenSource } from '../src/index'
import { mockTokenSource } from '../src/mock'
import { createWebhooksClient, verifyWebhookSignature } from '../src/webhooks'

const secret = 'whsec-test'
const payload = JSON.stringify({ hook: { system: 'data' }, resourceUrn: 'urn:x' })

function sign(body: string | Uint8Array, key = secret): string {
  return `sha1hash=${createHmac('sha1', key).update(body).digest('hex')}`
}

describe('verifyWebhookSignature', () => {
  it('verifies an HMAC-SHA1 signature over the raw body', async () => {
    await expect(
      verifyWebhookSignature({ payload, signature: sign(payload), secret }),
    ).resolves.toBe(true)
  })

  it('rejects a tampered signature', async () => {
    const good = sign(payload)
    const flipped = good.slice(0, -1) + (good.endsWith('0') ? '1' : '0')
    await expect(verifyWebhookSignature({ payload, signature: flipped, secret })).resolves.toBe(
      false,
    )
  })

  it('rejects a tampered payload', async () => {
    await expect(
      verifyWebhookSignature({ payload: `${payload} `, signature: sign(payload), secret }),
    ).resolves.toBe(false)
  })

  it('rejects a missing header, a wrong prefix, and odd-length hex', async () => {
    await expect(verifyWebhookSignature({ payload, signature: null, secret })).resolves.toBe(false)
    await expect(
      verifyWebhookSignature({
        payload,
        signature: sign(payload).replace('sha1hash=', ''),
        secret,
      }),
    ).resolves.toBe(false)
    await expect(
      verifyWebhookSignature({ payload, signature: 'sha1hash=abc', secret }),
    ).resolves.toBe(false)
    await expect(verifyWebhookSignature({ payload, signature: 'sha1hash=', secret })).resolves.toBe(
      false,
    )
  })

  it('accepts uppercase hex digests', async () => {
    await expect(
      verifyWebhookSignature({
        payload,
        signature: sign(payload).toUpperCase().replace('SHA1HASH=', 'sha1hash='),
        secret,
      }),
    ).resolves.toBe(true)
  })

  it('treats a Uint8Array payload like the equivalent string', async () => {
    const bytes = new TextEncoder().encode(payload)
    await expect(
      verifyWebhookSignature({ payload: bytes, signature: sign(payload), secret }),
    ).resolves.toBe(true)
  })

  it('rejects when the secret differs', async () => {
    await expect(
      verifyWebhookSignature({ payload, signature: sign(payload, 'other'), secret }),
    ).resolves.toBe(false)
  })
})

interface RecordedRequest {
  url: string
  method: string
  headers: Headers
  body: string | null
}

/** A fetch double that records every request and serves queued responses. */
function webhooksFetch(responses: Response[]) {
  const requests: RecordedRequest[] = []
  const wrapped: typeof fetch = async (input, init) => {
    requests.push({
      url: String(input),
      method: init?.method ?? 'GET',
      headers: new Headers(init?.headers),
      body: typeof init?.body === 'string' ? init.body : null,
    })
    const next = responses.shift()
    if (!next) throw new Error('no queued response left')
    return next
  }
  return { wrapped, requests }
}

/** Wraps a token source, recording each TokenRequest it receives. */
function recordingTokens(inner: TokenSource) {
  const requests: TokenRequest[] = []
  const wrapped: TokenSource = {
    getToken(request) {
      requests.push(request)
      return inner.getToken(request)
    },
  }
  return { wrapped, requests }
}

const subject = { type: 'app' } as const

describe('createWebhooksClient', () => {
  it('creates a hook and parses the hookId from the Location header', async () => {
    const { wrapped, requests } = webhooksFetch([
      new Response(null, {
        status: 201,
        headers: {
          Location:
            'https://developer.api.autodesk.com/webhooks/v1/systems/data/events/dm.version.added/hooks/hook-123',
        },
      }),
    ])
    const tokens = recordingTokens(mockTokenSource())
    const client = createWebhooksClient({
      tokens: tokens.wrapped,
      subject,
      region: 'EMEA',
      fetch: wrapped,
    })

    const created = await client.hooks.create({
      system: 'data',
      event: 'dm.version.added',
      callbackUrl: 'https://app.test/webhooks/aps',
      scope: { folder: 'urn:adsk.wipprod:fs.folder:co.abc' },
      hookAttribute: { projectId: 'p1' },
    })

    expect(created).toEqual({ hookId: 'hook-123' })
    const request = requests[0]
    expect(request?.url).toBe(
      'https://developer.api.autodesk.com/webhooks/v1/systems/data/events/dm.version.added/hooks',
    )
    expect(request?.method).toBe('POST')
    expect(request?.headers.get('authorization')).toBe('Bearer mock-aps-app')
    expect(request?.headers.get('x-ads-region')).toBe('EMEA')
    expect(request?.headers.get('content-type')).toBe('application/json')
    expect(JSON.parse(request?.body ?? '{}')).toEqual({
      callbackUrl: 'https://app.test/webhooks/aps',
      scope: { folder: 'urn:adsk.wipprod:fs.folder:co.abc' },
      hookAttribute: { projectId: 'p1' },
    })
    // Writes need data:write in the token.
    expect(tokens.requests[0]?.scopes).toEqual(['data:read', 'data:write'])
  })

  it('throws when create returns no Location header', async () => {
    const { wrapped } = webhooksFetch([new Response(null, { status: 201 })])
    const client = createWebhooksClient({ tokens: mockTokenSource(), subject, fetch: wrapped })

    await expect(
      client.hooks.create({
        system: 'data',
        event: 'dm.version.added',
        callbackUrl: 'https://app.test/cb',
        scope: { folder: 'urn:f' },
      }),
    ).rejects.toThrow(/no Location header/)
  })

  it('surfaces 409 as "already exists"', async () => {
    const { wrapped } = webhooksFetch([
      new Response(JSON.stringify({ detail: 'conflict' }), { status: 409 }),
    ])
    const client = createWebhooksClient({ tokens: mockTokenSource(), subject, fetch: wrapped })

    await expect(
      client.hooks.create({
        system: 'data',
        event: 'dm.version.added',
        callbackUrl: 'https://app.test/cb',
        scope: { folder: 'urn:f' },
      }),
    ).rejects.toThrow(/409.*already exists/)
  })

  it('lists hooks across pageState pages, re-requesting the original path', async () => {
    const hook = (hookId: string) => ({
      hookId,
      system: 'data',
      event: 'dm.version.added',
      status: 'active',
      callbackUrl: 'https://app.test/cb',
      scope: { folder: 'urn:f' },
    })
    const { wrapped, requests } = webhooksFetch([
      new Response(
        JSON.stringify({ links: { next: '/hooks?pageState=U1RBVEUx' }, data: [hook('h1')] }),
        { status: 200 },
      ),
      new Response(JSON.stringify({ links: {}, data: [hook('h2')] }), { status: 200 }),
    ])
    const tokens = recordingTokens(mockTokenSource())
    const client = createWebhooksClient({ tokens: tokens.wrapped, subject, fetch: wrapped })

    const seen: string[] = []
    for await (const record of client.hooks.list('data', 'dm.version.added')) {
      seen.push(record.hookId)
    }

    expect(seen).toEqual(['h1', 'h2'])
    expect(requests[0]?.url).toBe(
      'https://developer.api.autodesk.com/webhooks/v1/systems/data/events/dm.version.added/hooks',
    )
    expect(requests[1]?.url).toBe(
      'https://developer.api.autodesk.com/webhooks/v1/systems/data/events/dm.version.added/hooks?pageState=U1RBVEUx',
    )
    // Reads only need data:read.
    expect(tokens.requests[0]?.scopes).toEqual(['data:read'])
  })

  it('treats a queryless links.next as the pageState itself and stops on 204', async () => {
    const { wrapped, requests } = webhooksFetch([
      new Response(JSON.stringify({ links: { next: 'STATE2' }, data: [] }), { status: 200 }),
      new Response(null, { status: 204 }),
    ])
    const client = createWebhooksClient({ tokens: mockTokenSource(), subject, fetch: wrapped })

    const seen: unknown[] = []
    for await (const record of client.hooks.listApp()) seen.push(record)

    expect(seen).toEqual([])
    expect(requests[0]?.url).toBe('https://developer.api.autodesk.com/webhooks/v1/app/hooks')
    expect(requests[1]?.url).toBe(
      'https://developer.api.autodesk.com/webhooks/v1/app/hooks?pageState=STATE2',
    )
  })

  it('deletes a hook (204) with write scopes', async () => {
    const { wrapped, requests } = webhooksFetch([new Response(null, { status: 204 })])
    const tokens = recordingTokens(mockTokenSource())
    const client = createWebhooksClient({ tokens: tokens.wrapped, subject, fetch: wrapped })

    await client.hooks.delete('data', 'dm.version.added', 'hook-123')

    expect(requests[0]?.method).toBe('DELETE')
    expect(requests[0]?.url).toBe(
      'https://developer.api.autodesk.com/webhooks/v1/systems/data/events/dm.version.added/hooks/hook-123',
    )
    expect(tokens.requests[0]?.scopes).toEqual(['data:read', 'data:write'])
  })

  it('manages the secret token: set, update, remove', async () => {
    const { wrapped, requests } = webhooksFetch([
      new Response(null, { status: 200 }),
      new Response(null, { status: 200 }),
      new Response(null, { status: 204 }),
    ])
    const tokens = recordingTokens(mockTokenSource())
    const client = createWebhooksClient({ tokens: tokens.wrapped, subject, fetch: wrapped })

    await client.secretToken.set('s3cret')
    await client.secretToken.update('s3cret-2')
    await client.secretToken.remove()

    expect(requests.map((r) => [r.method, r.url])).toEqual([
      ['POST', 'https://developer.api.autodesk.com/webhooks/v1/tokens'],
      ['PUT', 'https://developer.api.autodesk.com/webhooks/v1/tokens/@me'],
      ['DELETE', 'https://developer.api.autodesk.com/webhooks/v1/tokens/@me'],
    ])
    expect(JSON.parse(requests[0]?.body ?? '{}')).toEqual({ token: 's3cret' })
    expect(JSON.parse(requests[1]?.body ?? '{}')).toEqual({ token: 's3cret-2' })
    for (const request of tokens.requests) {
      expect(request.scopes).toEqual(['data:read', 'data:write'])
    }
  })

  it('retries once with a force-refreshed token on 401', async () => {
    const { wrapped } = webhooksFetch([
      new Response(null, { status: 401 }),
      new Response(null, { status: 204 }),
    ])
    const tokens = recordingTokens(mockTokenSource())
    const client = createWebhooksClient({ tokens: tokens.wrapped, subject, fetch: wrapped })

    await client.hooks.delete('data', 'dm.version.added', 'h1')

    expect(tokens.requests).toHaveLength(2)
    expect(tokens.requests[1]?.forceRefresh).toBe(true)
  })

  it('retries a 429 honoring Retry-After', async () => {
    const { wrapped, requests } = webhooksFetch([
      new Response(null, { status: 429, headers: { 'Retry-After': '0' } }),
      new Response(null, { status: 204 }),
    ])
    const client = createWebhooksClient({ tokens: mockTokenSource(), subject, fetch: wrapped })

    await client.hooks.delete('data', 'dm.version.added', 'h1')

    expect(requests).toHaveLength(2)
  })

  it('omits x-ads-region when no region is configured', async () => {
    const { wrapped, requests } = webhooksFetch([new Response(null, { status: 204 })])
    const client = createWebhooksClient({ tokens: mockTokenSource(), subject, fetch: wrapped })

    await client.hooks.delete('data', 'dm.version.added', 'h1')

    expect(requests[0]?.headers.has('x-ads-region')).toBe(false)
  })
})
