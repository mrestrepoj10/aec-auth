import { afterEach, describe, expect, it, vi } from 'vitest'
import { createApsClient } from '../src/aps'
import type { TokenRequest, TokenSource } from '../src/index'
import { apsFixtures, mockApsFetch, mockTokenSource } from '../src/mock'

/** Wraps a fetch, recording headers of every request it sees. */
function recordingFetch(inner: typeof fetch) {
  const requests: { url: string; headers: Headers }[] = []
  const wrapped: typeof fetch = async (input, init) => {
    const request = new Request(input, init)
    requests.push({ url: request.url, headers: request.headers })
    return inner(input, init)
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

/** A fetch that 401s the first `times` requests, then delegates to `inner`. */
function unauthorizedThen(inner: typeof fetch, times: number): typeof fetch {
  let remaining = times
  return async (input, init) => {
    if (remaining > 0) {
      remaining -= 1
      return new Response(JSON.stringify({ error: 'token expired' }), { status: 401 })
    }
    return inner(input, init)
  }
}

/** A fetch that 429s the first `times` requests, then delegates to `inner`. */
function rateLimitedThen(inner: typeof fetch, times: number, retryAfter?: string) {
  let calls = 0
  const wrapped: typeof fetch = async (input, init) => {
    calls += 1
    if (calls <= times) {
      return new Response(JSON.stringify({ developerMessage: 'Quota limit exceeded.' }), {
        status: 429,
        headers: retryAfter === undefined ? {} : { 'Retry-After': retryAfter },
      })
    }
    return inner(input, init)
  }
  return { wrapped, count: () => calls }
}

describe('createApsClient', () => {
  const subject = { type: 'app' } as const

  it('lists and gets hubs and projects from the fixtures', async () => {
    const client = createApsClient({ tokens: mockTokenSource(), subject, fetch: mockApsFetch() })

    await expect(client.hubs.list()).resolves.toEqual({ data: apsFixtures.hubs })
    await expect(client.hubs.get('b.mock-hub-1')).resolves.toEqual({ data: apsFixtures.hubs[0] })
    await expect(client.projects.list('b.mock-hub-2')).resolves.toEqual({
      data: apsFixtures.projects['b.mock-hub-2'],
    })
    await expect(client.projects.get('b.mock-hub-1', 'b.mock-project-2')).resolves.toEqual({
      data: apsFixtures.projects['b.mock-hub-1']?.[1],
    })
  })

  it('sends the Authorization header from the token source', async () => {
    const { wrapped, requests } = recordingFetch(mockApsFetch())
    const client = createApsClient({ tokens: mockTokenSource(), subject, fetch: wrapped })

    await client.hubs.list()

    expect(requests[0]?.headers.get('authorization')).toBe('Bearer mock-aps-app')
  })

  it('requests data:read scopes for the configured subject', async () => {
    const { wrapped, requests } = recordingTokens(mockTokenSource())
    const client = createApsClient({
      tokens: wrapped,
      subject: { type: 'user', id: 'u1' },
      fetch: mockApsFetch(),
    })

    await client.hubs.list()

    expect(requests[0]).toMatchObject({
      provider: 'aps',
      subject: { type: 'user', id: 'u1' },
      scopes: ['data:read'],
    })
  })

  it('retries once with forceRefresh on a 401', async () => {
    const { wrapped, requests } = recordingTokens(mockTokenSource())
    const client = createApsClient({
      tokens: wrapped,
      subject,
      fetch: unauthorizedThen(mockApsFetch(), 1),
    })

    await expect(client.hubs.list()).resolves.toEqual({ data: apsFixtures.hubs })
    expect(requests).toHaveLength(2)
    expect(requests[0]?.forceRefresh).toBeUndefined()
    expect(requests[1]?.forceRefresh).toBe(true)
  })

  it('throws with status and body when the retry also 401s', async () => {
    const client = createApsClient({
      tokens: mockTokenSource(),
      subject,
      fetch: unauthorizedThen(mockApsFetch(), 2),
    })

    await expect(client.hubs.list()).rejects.toThrow(/401.*token expired/)
  })

  it('throws with status and body on other API errors', async () => {
    const client = createApsClient({ tokens: mockTokenSource(), subject, fetch: mockApsFetch() })

    await expect(client.hubs.get('b.nope')).rejects.toThrow(/404.*not_found/)
  })

  it('exposes a generic request escape hatch', async () => {
    const client = createApsClient({ tokens: mockTokenSource(), subject, fetch: mockApsFetch() })

    await expect(client.request('/project/v1/hubs')).resolves.toEqual({ data: apsFixtures.hubs })
  })
})

describe('createApsClient — 429 retry', () => {
  const subject = { type: 'app' } as const

  afterEach(() => {
    vi.useRealTimers()
  })

  it('retries a 429 with Retry-After: 0 and succeeds', async () => {
    const { wrapped, count } = rateLimitedThen(mockApsFetch(), 1, '0')
    const client = createApsClient({ tokens: mockTokenSource(), subject, fetch: wrapped })

    await expect(client.hubs.list()).resolves.toEqual({ data: apsFixtures.hubs })
    expect(count()).toBe(2)
  })

  it('waits exactly the number of seconds the Retry-After header names', async () => {
    vi.useFakeTimers()
    const { wrapped, count } = rateLimitedThen(mockApsFetch(), 1, '25')
    const client = createApsClient({ tokens: mockTokenSource(), subject, fetch: wrapped })

    const pending = client.hubs.list()
    await vi.advanceTimersByTimeAsync(24_999)
    expect(count()).toBe(1)
    await vi.advanceTimersByTimeAsync(1)
    await expect(pending).resolves.toEqual({ data: apsFixtures.hubs })
    expect(count()).toBe(2)
  })

  it('falls back to jittered exponential backoff when no header is present', async () => {
    vi.useFakeTimers()
    const { wrapped, count } = rateLimitedThen(mockApsFetch(), 1)
    const client = createApsClient({ tokens: mockTokenSource(), subject, fetch: wrapped })

    const pending = client.hubs.list()
    // First-attempt backoff is 1000ms base + jitter in [0, 1000).
    await vi.advanceTimersByTimeAsync(999)
    expect(count()).toBe(1)
    await vi.advanceTimersByTimeAsync(1_001)
    await expect(pending).resolves.toEqual({ data: apsFixtures.hubs })
    expect(count()).toBe(2)
  })

  it('gives up after three retries and throws with the 429 status', async () => {
    const { wrapped, count } = rateLimitedThen(mockApsFetch(), 4, '0')
    const client = createApsClient({ tokens: mockTokenSource(), subject, fetch: wrapped })

    await expect(client.hubs.list()).rejects.toThrow(/429.*Quota limit exceeded/)
    expect(count()).toBe(4)
  })

  it('does not retry a ReadableStream body', async () => {
    const { wrapped, count } = rateLimitedThen(mockApsFetch(), 1, '0')
    const client = createApsClient({ tokens: mockTokenSource(), subject, fetch: wrapped })
    const body = new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('{}'))
        controller.close()
      },
    })

    await expect(
      client.request('/project/v1/hubs', { method: 'POST', body, duplex: 'half' } as RequestInit),
    ).rejects.toThrow(/429/)
    expect(count()).toBe(1)
  })

  it('composes with the 401 refresh: refresh once, then backoff', async () => {
    const statuses = [401, 429]
    let calls = 0
    const inner = mockApsFetch()
    const sequenced: typeof fetch = async (input, init) => {
      const status = statuses[calls]
      calls += 1
      if (status !== undefined) {
        return new Response(JSON.stringify({ error: 'nope' }), {
          status,
          headers: { 'Retry-After': '0' },
        })
      }
      return inner(input, init)
    }
    const { wrapped: tokens, requests } = recordingTokens(mockTokenSource())
    const client = createApsClient({ tokens, subject, fetch: sequenced })

    await expect(client.hubs.list()).resolves.toEqual({ data: apsFixtures.hubs })
    expect(calls).toBe(3)
    expect(requests[0]?.forceRefresh).toBeUndefined()
    expect(requests[1]?.forceRefresh).toBe(true)
    expect(requests[2]?.forceRefresh).toBeUndefined()
  })
})

describe('mockApsFetch', () => {
  it('rejects requests without an Authorization header', async () => {
    const response = await mockApsFetch()('https://developer.api.autodesk.com/project/v1/hubs')

    expect(response.status).toBe(401)
  })

  it('404 on unknown routes', async () => {
    const response = await mockApsFetch()('https://developer.api.autodesk.com/unknown', {
      headers: { Authorization: 'Bearer x' },
    })

    expect(response.status).toBe(404)
  })
})
