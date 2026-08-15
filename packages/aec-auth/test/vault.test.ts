import { afterEach, describe, expect, it, vi } from 'vitest'
import { TokenError, type TokenRequest } from '../src/index'
import {
  memoryVaultStore,
  type OAuthProvider,
  type OAuthTokenResult,
  saveUserGrant,
  type UserGrant,
  vaultTokenSource,
} from '../src/vault'

const userRequest: TokenRequest = { provider: 'aps', subject: { type: 'user', id: 'u1' } }
const appRequest: TokenRequest = {
  provider: 'aps',
  subject: { type: 'app' },
  scopes: ['data:read'],
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

/**
 * A provider whose refresh tokens are strictly single-use: refreshing with
 * anything but the current, never-used token throws invalid_grant — exactly
 * how APS behaves. Latency makes the refresh window wide enough to race.
 */
function singleUseRefreshProvider(latencyMs = 20) {
  const used = new Set<string>()
  let current = 'rt-1'
  let mints = 0
  const refresh = vi.fn(async (refreshToken: string): Promise<OAuthTokenResult> => {
    await delay(latencyMs)
    if (used.has(refreshToken) || refreshToken !== current) {
      throw new TokenError('grant_invalid', 'aps', 'invalid_grant: refresh token already used')
    }
    used.add(refreshToken)
    mints += 1
    current = `rt-${mints + 1}`
    return {
      accessToken: { token: `at-${mints}`, expiresAt: Date.now() + 3_600_000 },
      refreshToken: current,
    }
  })
  const clientCredentials = vi.fn(async (): Promise<OAuthTokenResult> => {
    mints += 1
    return { accessToken: { token: `app-${mints}`, expiresAt: Date.now() + 3_600_000 } }
  })
  const provider: OAuthProvider = {
    provider: 'aps',
    clientCredentials,
    refresh,
    exchangeCode: async () => {
      throw new Error('exchangeCode not used in these tests')
    },
    authorizeUrl: () => 'https://example.test/authorize',
  }
  return { provider, refresh, clientCredentials, currentRefreshToken: () => current }
}

const grant = (): UserGrant => ({ refreshToken: 'rt-1', obtainedAt: Date.now() })

afterEach(() => {
  vi.useRealTimers()
})

describe('vaultTokenSource — user tokens', () => {
  it('N concurrent calls on one instance perform exactly one refresh', async () => {
    const store = memoryVaultStore()
    const { provider, refresh } = singleUseRefreshProvider()
    await saveUserGrant(store, 'aps', 'u1', grant())
    const source = vaultTokenSource({ store, providers: { aps: provider } })

    const tokens = await Promise.all(Array.from({ length: 5 }, () => source.getToken(userRequest)))

    expect(refresh).toHaveBeenCalledTimes(1)
    expect(new Set(tokens.map((t) => t.token))).toEqual(new Set(['at-1']))
  })

  it('two instances sharing a store serialize on the lock; the grant survives', async () => {
    const store = memoryVaultStore()
    const { provider, refresh } = singleUseRefreshProvider()
    await saveUserGrant(store, 'aps', 'u1', grant())
    const a = vaultTokenSource({ store, providers: { aps: provider } })
    const b = vaultTokenSource({ store, providers: { aps: provider } })

    // Two "serverless instances" race. Without the lock, both would spend
    // rt-1 and one would hit invalid_grant, destroying the grant.
    const [tokenA, tokenB] = await Promise.all([a.getToken(userRequest), b.getToken(userRequest)])

    expect(refresh).toHaveBeenCalledTimes(1)
    expect(tokenA.token).toBe('at-1')
    expect(tokenB.token).toBe('at-1')

    const storedGrant = await store.get('aec-auth:grant:aps:u1')
    expect(storedGrant).not.toBeNull()
    expect(JSON.parse(storedGrant ?? '{}')).toMatchObject({ refreshToken: 'rt-2' })
  })

  it('persists the rotated refresh token so the next refresh succeeds', async () => {
    const store = memoryVaultStore()
    const { provider, refresh, currentRefreshToken } = singleUseRefreshProvider(0)
    await saveUserGrant(store, 'aps', 'u1', grant())
    const source = vaultTokenSource({ store, providers: { aps: provider } })

    const first = await source.getToken(userRequest)
    expect(first.token).toBe('at-1')

    // forceRefresh must use the persisted rt-2 — replaying rt-1 would throw.
    const second = await source.getToken({ ...userRequest, forceRefresh: true })
    expect(second.token).toBe('at-2')
    expect(refresh).toHaveBeenCalledTimes(2)
    expect(refresh).toHaveBeenLastCalledWith('rt-2', undefined)
    expect(currentRefreshToken()).toBe('rt-3')
  })

  it('returns the cached access token without refreshing while fresh', async () => {
    const store = memoryVaultStore()
    const { provider, refresh } = singleUseRefreshProvider(0)
    await saveUserGrant(store, 'aps', 'u1', grant())
    const source = vaultTokenSource({ store, providers: { aps: provider } })

    const first = await source.getToken(userRequest)
    const second = await source.getToken(userRequest)
    expect(second.token).toBe(first.token)
    expect(refresh).toHaveBeenCalledTimes(1)
  })

  it('missing grant throws consent_required', async () => {
    const store = memoryVaultStore()
    const { provider, refresh } = singleUseRefreshProvider()
    const source = vaultTokenSource({ store, providers: { aps: provider } })

    const error = await source.getToken(userRequest).catch((e: unknown) => e)
    expect(error).toBeInstanceOf(TokenError)
    expect((error as TokenError).code).toBe('consent_required')
    expect(refresh).not.toHaveBeenCalled()
  })

  it('unconfigured provider throws not_configured', async () => {
    const source = vaultTokenSource({ store: memoryVaultStore(), providers: {} })
    const error = await source.getToken(userRequest).catch((e: unknown) => e)
    expect(error).toBeInstanceOf(TokenError)
    expect((error as TokenError).code).toBe('not_configured')
  })

  it('fails cleanly instead of racing when the lock holder never publishes', async () => {
    vi.useFakeTimers()
    const store = memoryVaultStore()
    const { provider, refresh } = singleUseRefreshProvider(0)
    await saveUserGrant(store, 'aps', 'u1', grant())
    // Simulate a crashed process that still holds the refresh lock.
    await store.acquireLock('aec-auth:lock:aps:user:u1', 60_000)
    const source = vaultTokenSource({ store, providers: { aps: provider } })

    const pending = source.getToken(userRequest)
    const assertion = expect(pending).rejects.toMatchObject({
      name: 'TokenError',
      code: 'provider_error',
    })
    await vi.advanceTimersByTimeAsync(10_000)
    await assertion
    expect(refresh).not.toHaveBeenCalled()
  })
})

describe('vaultTokenSource — app tokens', () => {
  it('mints via client_credentials and caches in the store', async () => {
    const store = memoryVaultStore()
    const { provider, clientCredentials } = singleUseRefreshProvider()
    const source = vaultTokenSource({ store, providers: { aps: provider } })

    const first = await source.getToken(appRequest)
    const second = await source.getToken(appRequest)
    expect(second.token).toBe(first.token)
    expect(clientCredentials).toHaveBeenCalledTimes(1)
    expect(clientCredentials).toHaveBeenCalledWith(['data:read'])
  })

  it('single-flights concurrent app mints', async () => {
    const store = memoryVaultStore()
    const { provider, clientCredentials } = singleUseRefreshProvider()
    const source = vaultTokenSource({ store, providers: { aps: provider } })

    const tokens = await Promise.all(Array.from({ length: 4 }, () => source.getToken(appRequest)))
    expect(clientCredentials).toHaveBeenCalledTimes(1)
    expect(new Set(tokens.map((t) => t.token)).size).toBe(1)
  })
})

describe('memoryVaultStore', () => {
  it('expires values and locks by TTL', async () => {
    vi.useFakeTimers()
    const store = memoryVaultStore()

    await store.set('k', 'v', { ttlMs: 1_000 })
    expect(await store.get('k')).toBe('v')
    const first = await store.acquireLock('lock', 1_000)
    expect(first).not.toBeNull()
    expect(await store.acquireLock('lock', 1_000)).toBeNull()

    vi.advanceTimersByTime(1_500)
    expect(await store.get('k')).toBeNull()
    const second = await store.acquireLock('lock', 1_000)
    expect(second).not.toBeNull()

    await store.releaseLock('lock', second as string)
    expect(await store.acquireLock('lock', 1_000)).not.toBeNull()
  })

  it('release with a stale lease cannot delete a newer holder’s lock', async () => {
    vi.useFakeTimers()
    const store = memoryVaultStore()

    // Holder A acquires, then stalls past its TTL.
    const leaseA = (await store.acquireLock('lock', 1_000)) as string
    vi.advanceTimersByTime(1_500)

    // Holder B acquires the now-expired lock.
    const leaseB = await store.acquireLock('lock', 60_000)
    expect(leaseB).not.toBeNull()

    // A finally finishes and releases with its stale lease: must be a no-op.
    await store.releaseLock('lock', leaseA)
    expect(await store.acquireLock('lock', 1_000)).toBeNull()

    // B's own release still works.
    await store.releaseLock('lock', leaseB as string)
    expect(await store.acquireLock('lock', 1_000)).not.toBeNull()
  })

  it('persists values without a TTL and deletes on request', async () => {
    const store = memoryVaultStore()
    await store.set('k', 'v')
    expect(await store.get('k')).toBe('v')
    await store.delete('k')
    expect(await store.get('k')).toBeNull()
  })
})
