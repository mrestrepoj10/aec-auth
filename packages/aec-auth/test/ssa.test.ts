import { describe, expect, it } from 'vitest'
import { apsScopes, type TokenRequest, type TokenSource } from '../src/index'
import { mockTokenSource } from '../src/mock'
import { createSsaAdminClient } from '../src/ssa'

interface RecordedRequest {
  url: string
  method: string
  headers: Headers
  body: string | null
}

/** A fetch double that records every request and serves queued responses. */
function ssaFetch(responses: Response[]) {
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

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status })
}

const account = {
  serviceAccountId: 'SA1',
  email: 'bot@cid.adskserviceaccount.autodesk.com',
  status: 'ENABLED',
} as const

describe('createSsaAdminClient — accounts', () => {
  it('creates an account with the write scope and an app subject', async () => {
    const { wrapped, requests } = ssaFetch([json(account, 201)])
    const tokens = recordingTokens(mockTokenSource())
    const client = createSsaAdminClient({ tokens: tokens.wrapped, fetch: wrapped })

    const created = await client.accounts.create({
      name: 'ci-bot',
      firstName: 'CI',
      lastName: 'Bot',
    })

    expect(created).toMatchObject({ serviceAccountId: 'SA1' })
    const request = requests[0]
    expect(request?.method).toBe('POST')
    expect(request?.url).toBe(
      'https://developer.api.autodesk.com/authentication/v2/service-accounts',
    )
    expect(request?.headers.get('authorization')).toBe('Bearer mock-aps-app')
    expect(JSON.parse(request?.body ?? '{}')).toEqual({
      name: 'ci-bot',
      firstName: 'CI',
      lastName: 'Bot',
    })
    expect(tokens.requests[0]).toMatchObject({
      subject: { type: 'app' },
      scopes: ['application:service_account:write'],
    })
  })

  it('maps a 403 on create to the 10-account limit', async () => {
    const { wrapped } = ssaFetch([json({ developerMessage: 'forbidden' }, 403)])
    const client = createSsaAdminClient({ tokens: mockTokenSource(), fetch: wrapped })

    await expect(
      client.accounts.create({ name: 'ci-bot', firstName: 'CI', lastName: 'Bot' }),
    ).rejects.toThrow(/403.*10 service accounts/)
  })

  it('lists, gets, and patches accounts with read/write scopes', async () => {
    const { wrapped, requests } = ssaFetch([
      json({ serviceAccounts: [account] }),
      json(account),
      json({ ...account, status: 'DISABLED' }),
    ])
    const tokens = recordingTokens(mockTokenSource())
    const client = createSsaAdminClient({ tokens: tokens.wrapped, fetch: wrapped })

    await expect(client.accounts.list()).resolves.toEqual([account])
    await expect(client.accounts.get('SA1')).resolves.toEqual(account)
    await expect(client.accounts.setStatus('SA1', 'DISABLED')).resolves.toMatchObject({
      status: 'DISABLED',
    })

    expect(requests.map((r) => [r.method, r.url])).toEqual([
      ['GET', 'https://developer.api.autodesk.com/authentication/v2/service-accounts'],
      ['GET', 'https://developer.api.autodesk.com/authentication/v2/service-accounts/SA1'],
      ['PATCH', 'https://developer.api.autodesk.com/authentication/v2/service-accounts/SA1'],
    ])
    expect(JSON.parse(requests[2]?.body ?? '{}')).toEqual({ status: 'DISABLED' })
    expect(tokens.requests[0]?.scopes).toEqual([
      'application:service_account:read',
      'application:service_account_key:read',
    ])
    expect(tokens.requests[2]?.scopes).toEqual(['application:service_account:write'])
  })

  it('deletes an account (204)', async () => {
    const { wrapped, requests } = ssaFetch([new Response(null, { status: 204 })])
    const client = createSsaAdminClient({ tokens: mockTokenSource(), fetch: wrapped })

    await expect(client.accounts.delete('SA1')).resolves.toBeUndefined()
    expect(requests[0]?.method).toBe('DELETE')
  })
})

describe('createSsaAdminClient — keys', () => {
  it('creates a key with no body and returns the one-time privateKey', async () => {
    const { wrapped, requests } = ssaFetch([
      json({ kid: 'k1', privateKey: '-----BEGIN RSA PRIVATE KEY-----\\n...' }, 201),
    ])
    const tokens = recordingTokens(mockTokenSource())
    const client = createSsaAdminClient({ tokens: tokens.wrapped, fetch: wrapped })

    const key = await client.keys.create('SA1')

    expect(key.kid).toBe('k1')
    expect(key.privateKey).toContain('BEGIN RSA PRIVATE KEY')
    const request = requests[0]
    expect(request?.method).toBe('POST')
    expect(request?.url).toBe(
      'https://developer.api.autodesk.com/authentication/v2/service-accounts/SA1/keys',
    )
    expect(request?.body).toBeNull()
    expect(tokens.requests[0]?.scopes).toEqual(['application:service_account_key:write'])
  })

  it('maps a 403 on key create to the 3-key limit', async () => {
    const { wrapped } = ssaFetch([json({ developerMessage: 'forbidden' }, 403)])
    const client = createSsaAdminClient({ tokens: mockTokenSource(), fetch: wrapped })

    await expect(client.keys.create('SA1')).rejects.toThrow(/403.*3 keys/)
  })

  it('lists key metadata with read scopes', async () => {
    const keys = [{ kid: 'k1', status: 'ENABLED' }]
    const { wrapped } = ssaFetch([json({ keys })])
    const tokens = recordingTokens(mockTokenSource())
    const client = createSsaAdminClient({ tokens: tokens.wrapped, fetch: wrapped })

    await expect(client.keys.list('SA1')).resolves.toEqual(keys)
    expect(tokens.requests[0]?.scopes).toEqual([
      'application:service_account:read',
      'application:service_account_key:read',
    ])
  })

  it('patches and deletes keys (204) with the key write scope', async () => {
    const { wrapped, requests } = ssaFetch([
      new Response(null, { status: 204 }),
      new Response(null, { status: 204 }),
    ])
    const tokens = recordingTokens(mockTokenSource())
    const client = createSsaAdminClient({ tokens: tokens.wrapped, fetch: wrapped })

    await expect(client.keys.setStatus('SA1', 'k1', 'DISABLED')).resolves.toBeUndefined()
    await expect(client.keys.delete('SA1', 'k1')).resolves.toBeUndefined()

    expect(requests.map((r) => [r.method, r.url])).toEqual([
      [
        'PATCH',
        'https://developer.api.autodesk.com/authentication/v2/service-accounts/SA1/keys/k1',
      ],
      [
        'DELETE',
        'https://developer.api.autodesk.com/authentication/v2/service-accounts/SA1/keys/k1',
      ],
    ])
    expect(JSON.parse(requests[0]?.body ?? '{}')).toEqual({ status: 'DISABLED' })
    for (const request of tokens.requests) {
      expect(request.scopes).toEqual(['application:service_account_key:write'])
    }
  })

  it('retries 429s honoring Retry-After (every SSA endpoint is 10 req/min)', async () => {
    const { wrapped, requests } = ssaFetch([
      new Response(null, { status: 429, headers: { 'Retry-After': '0' } }),
      json({ serviceAccounts: [] }),
    ])
    const client = createSsaAdminClient({ tokens: mockTokenSource(), fetch: wrapped })

    await expect(client.accounts.list()).resolves.toEqual([])
    expect(requests).toHaveLength(2)
  })
})

describe('apsScopes.ssaAdmin', () => {
  it('bundles the four management scopes', () => {
    expect(apsScopes.ssaAdmin).toEqual([
      'application:service_account:read',
      'application:service_account:write',
      'application:service_account_key:read',
      'application:service_account_key:write',
    ])
  })
})
