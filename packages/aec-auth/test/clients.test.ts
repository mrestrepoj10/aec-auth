import { describe, expect, it } from 'vitest'
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
