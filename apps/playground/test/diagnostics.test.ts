import { afterEach, describe, expect, it, vi } from 'vitest'
import { GET } from '../app/api/token/route'
import { type Check, createChecksRunner } from '../lib/checks'
import { isDiagnosticsAuthorized } from '../lib/diagnostics-auth'

afterEach(() => {
  vi.unstubAllEnvs()
})

describe('diagnostics authorization', () => {
  it('allows the local dev server without a token, but never production builds', async () => {
    vi.stubEnv('NODE_ENV', 'development')
    vi.stubEnv('PLAYGROUND_DIAGNOSTICS_TOKEN', '')
    await expect(
      isDiagnosticsAuthorized(new Request('https://example.test/api/token')),
    ).resolves.toBe(true)

    vi.stubEnv('NODE_ENV', 'production')
    await expect(
      isDiagnosticsAuthorized(new Request('https://example.test/api/token')),
    ).resolves.toBe(false)
  })

  it('fails closed when the token is not configured', async () => {
    vi.stubEnv('PLAYGROUND_DIAGNOSTICS_TOKEN', '')
    const request = new Request('https://example.test/api/token', {
      headers: { Authorization: 'Bearer guessed' },
    })
    await expect(isDiagnosticsAuthorized(request)).resolves.toBe(false)
  })

  it('returns only a generic 401 without running diagnostics', async () => {
    vi.stubEnv('PLAYGROUND_DIAGNOSTICS_TOKEN', '')
    const response = await GET(new Request('https://example.test/api/token'))

    expect(response.status).toBe(401)
    expect(await response.json()).toEqual({ ok: false, error: 'unauthorized' })
    expect(response.headers.get('cache-control')).toBe('no-store')
  })

  it('accepts only the configured bearer token', async () => {
    vi.stubEnv('PLAYGROUND_DIAGNOSTICS_TOKEN', 'admin-secret')
    const authorized = new Request('https://example.test/api/token', {
      headers: { Authorization: 'Bearer admin-secret' },
    })
    const rejected = new Request('https://example.test/api/token', {
      headers: { Authorization: 'Bearer wrong' },
    })

    await expect(isDiagnosticsAuthorized(authorized)).resolves.toBe(true)
    await expect(isDiagnosticsAuthorized(rejected)).resolves.toBe(false)
  })
})

describe('createChecksRunner', () => {
  it('coalesces concurrent checks and reuses results until the TTL expires', async () => {
    let now = 1_000
    const result: Check = { name: 'live', how: 'test', status: 'pass', detail: 'ok' }
    const task = vi.fn(async () => result)
    const run = createChecksRunner([task], { ttlMs: 60_000, now: () => now })

    const [first, second] = await Promise.all([run(), run()])
    expect(first).toBe(second)
    expect(task).toHaveBeenCalledTimes(1)

    expect(await run()).toBe(first)
    expect(task).toHaveBeenCalledTimes(1)

    now += 60_001
    expect(await run()).not.toBe(first)
    expect(task).toHaveBeenCalledTimes(2)
  })
})
