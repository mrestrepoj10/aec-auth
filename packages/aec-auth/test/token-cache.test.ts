import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  type AccessToken,
  requestKey,
  type TokenRequest,
  type TokenSource,
  withTokenCache,
} from '../src/index'

const request: TokenRequest = {
  provider: 'aps',
  subject: { type: 'app' },
  scopes: ['data:read'],
}

function tokenExpiringIn(ms: number, token: string): AccessToken {
  return { token, expiresAt: Date.now() + ms }
}

function countingSource(): TokenSource & { calls: () => number } {
  let calls = 0
  return {
    calls: () => calls,
    async getToken() {
      calls += 1
      return tokenExpiringIn(3_600_000, `t${calls}`)
    },
  }
}

describe('withTokenCache', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-01-01T00:00:00Z'))
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('caches a fresh token until expiry', async () => {
    const upstream = countingSource()
    const cached = withTokenCache(upstream)
    const first = await cached.getToken(request)
    const second = await cached.getToken(request)
    expect(second).toBe(first)
    expect(upstream.calls()).toBe(1)
  })

  it('refetches after the token expires', async () => {
    const upstream = countingSource()
    const cached = withTokenCache(upstream)
    const first = await cached.getToken(request)
    vi.advanceTimersByTime(4_000_000)
    const second = await cached.getToken(request)
    expect(second.token).not.toBe(first.token)
    expect(upstream.calls()).toBe(2)
  })

  it('treats a token inside the expiry skew as expired', async () => {
    const upstream = countingSource()
    const cached = withTokenCache(upstream)
    await cached.getToken(request)
    // 3_590_000ms in, the token has 10s left — inside the 30s skew.
    vi.advanceTimersByTime(3_590_000)
    await cached.getToken(request)
    expect(upstream.calls()).toBe(2)
  })

  it('dedupes concurrent calls into one upstream request', async () => {
    let release!: (token: AccessToken) => void
    const gate = new Promise<AccessToken>((resolve) => {
      release = resolve
    })
    const getToken = vi.fn(() => gate)
    const cached = withTokenCache({ getToken })
    const first = cached.getToken(request)
    const second = cached.getToken(request)
    release(tokenExpiringIn(3_600_000, 'shared'))
    const [a, b] = await Promise.all([first, second])
    expect(a).toBe(b)
    expect(getToken).toHaveBeenCalledTimes(1)
  })

  it('forceRefresh bypasses the cache', async () => {
    const upstream = countingSource()
    const cached = withTokenCache(upstream)
    const first = await cached.getToken(request)
    const forced = await cached.getToken({ ...request, forceRefresh: true })
    expect(forced.token).not.toBe(first.token)
    expect(upstream.calls()).toBe(2)
    // The forced token replaces the cached one.
    const third = await cached.getToken(request)
    expect(third).toBe(forced)
    expect(upstream.calls()).toBe(2)
  })

  it('single-flights concurrent forceRefresh calls', async () => {
    const upstream = countingSource()
    const cached = withTokenCache(upstream)
    await cached.getToken(request)

    const forced = await Promise.all(
      Array.from({ length: 4 }, () => cached.getToken({ ...request, forceRefresh: true })),
    )

    expect(upstream.calls()).toBe(2)
    expect(new Set(forced.map((token) => token.token))).toEqual(new Set(['t2']))
  })

  it('makes normal callers join an active forced refresh instead of returning stale cache data', async () => {
    let release!: (token: AccessToken) => void
    const forcedToken = new Promise<AccessToken>((resolve) => {
      release = resolve
    })
    const getToken = vi
      .fn<() => Promise<AccessToken>>()
      .mockResolvedValueOnce(tokenExpiringIn(3_600_000, 'stale'))
      .mockReturnValueOnce(forcedToken)
    const cached = withTokenCache({ getToken })
    await cached.getToken(request)

    const forced = cached.getToken({ ...request, forceRefresh: true })
    const normal = cached.getToken(request)
    release(tokenExpiringIn(3_600_000, 'replacement'))

    const [forcedResult, normalResult] = await Promise.all([forced, normal])
    expect(forcedResult.token).toBe('replacement')
    expect(normalResult).toBe(forcedResult)
    expect(getToken).toHaveBeenCalledTimes(2)
  })
})

describe('requestKey', () => {
  it('cannot collide when user IDs and scopes contain delimiters', () => {
    const victim = requestKey({
      provider: 'aps',
      subject: { type: 'user', id: 'victim' },
      scopes: ['data:read'],
    })
    const attacker = requestKey({
      provider: 'aps',
      subject: { type: 'user', id: 'victim:data' },
      scopes: ['read'],
    })

    expect(attacker).not.toBe(victim)
  })

  it('normalizes scope order while distinguishing omitted and empty scopes', () => {
    expect(requestKey({ ...request, scopes: ['viewables:read', 'data:read'] })).toBe(
      requestKey({ ...request, scopes: ['data:read', 'viewables:read'] }),
    )
    expect(requestKey({ ...request, scopes: undefined })).not.toBe(
      requestKey({ ...request, scopes: [] }),
    )
  })

  it('keeps delimiter-containing users isolated in the actual token cache', async () => {
    const getToken = vi.fn(async (tokenRequest: TokenRequest) =>
      tokenExpiringIn(
        3_600_000,
        tokenRequest.subject.type === 'user' ? tokenRequest.subject.id : 'app',
      ),
    )
    const cached = withTokenCache({ getToken })
    const victimRequest: TokenRequest = {
      provider: 'aps',
      subject: { type: 'user', id: 'victim' },
      scopes: ['data:read'],
    }
    const attackerRequest: TokenRequest = {
      provider: 'aps',
      subject: { type: 'user', id: 'victim:data' },
      scopes: ['read'],
    }

    expect((await cached.getToken(victimRequest)).token).toBe('victim')
    expect((await cached.getToken(attackerRequest)).token).toBe('victim:data')
    expect(getToken).toHaveBeenCalledTimes(2)
  })
})
