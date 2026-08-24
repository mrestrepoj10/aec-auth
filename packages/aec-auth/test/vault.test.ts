import { afterEach, describe, expect, it, vi } from 'vitest'
import { TokenError, type TokenRequest } from '../src/index'
import {
  deleteUserGrant,
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

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((resolvePromise) => {
    resolve = resolvePromise
  })
  return { promise, resolve }
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
  const serviceAccount = vi.fn(async (serviceAccountId: string): Promise<OAuthTokenResult> => {
    await delay(latencyMs)
    mints += 1
    return {
      accessToken: { token: `sa-${serviceAccountId}-${mints}`, expiresAt: Date.now() + 3_600_000 },
    }
  })
  const provider: OAuthProvider = {
    provider: 'aps',
    clientCredentials,
    refresh,
    serviceAccount,
    exchangeCode: async () => {
      throw new Error('exchangeCode not used in these tests')
    },
    authorizeUrl: () => 'https://example.test/authorize',
  }
  return {
    provider,
    refresh,
    clientCredentials,
    serviceAccount,
    currentRefreshToken: () => current,
  }
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

  it('single-flights concurrent forceRefresh calls in one instance', async () => {
    const store = memoryVaultStore()
    const { provider, refresh } = singleUseRefreshProvider(20)
    await saveUserGrant(store, 'aps', 'u1', grant())
    const source = vaultTokenSource({ store, providers: { aps: provider } })
    await source.getToken(userRequest)

    const tokens = await Promise.all(
      Array.from({ length: 5 }, () => source.getToken({ ...userRequest, forceRefresh: true })),
    )

    expect(refresh).toHaveBeenCalledTimes(2)
    expect(new Set(tokens.map((token) => token.token))).toEqual(new Set(['at-2']))
  })

  it('renews a long refresh lease and returns only the replacement to a forced loser', async () => {
    vi.useFakeTimers()
    const store = memoryVaultStore()
    const refreshStarted = deferred<void>()
    const releaseRefresh = deferred<void>()
    let refreshes = 0
    const refresh = vi.fn(async (_refreshToken: string): Promise<OAuthTokenResult> => {
      refreshes += 1
      if (refreshes === 2) {
        refreshStarted.resolve()
        await releaseRefresh.promise
      }
      return {
        accessToken: { token: `at-${refreshes}`, expiresAt: Date.now() + 3_600_000 },
        refreshToken: `rt-${refreshes + 1}`,
      }
    })
    const provider: OAuthProvider = {
      ...singleUseRefreshProvider(0).provider,
      refresh,
    }
    await saveUserGrant(store, 'aps', 'u1', grant())
    const firstInstance = vaultTokenSource({ store, providers: { aps: provider } })
    const secondInstance = vaultTokenSource({ store, providers: { aps: provider } })
    expect((await firstInstance.getToken(userRequest)).token).toBe('at-1')

    const winner = firstInstance.getToken({ ...userRequest, forceRefresh: true })
    await refreshStarted.promise
    await vi.advanceTimersByTimeAsync(15_000)
    const loser = secondInstance.getToken({ ...userRequest, forceRefresh: true })
    await Promise.resolve()
    expect(refresh).toHaveBeenCalledTimes(2)

    releaseRefresh.resolve()
    await vi.advanceTimersByTimeAsync(250)
    const [winnerToken, loserToken] = await Promise.all([winner, loser])
    expect(winnerToken.token).toBe('at-2')
    expect(loserToken.token).toBe('at-2')
    expect(refresh).toHaveBeenCalledTimes(2)
  })

  it('serializes deletion with refresh and invalidates cached tokens', async () => {
    const store = memoryVaultStore()
    const refreshStarted = deferred<void>()
    const releaseRefresh = deferred<void>()
    const refresh = vi.fn(async (): Promise<OAuthTokenResult> => {
      refreshStarted.resolve()
      await releaseRefresh.promise
      return {
        accessToken: { token: 'refreshed', expiresAt: Date.now() + 3_600_000 },
        refreshToken: 'rt-2',
      }
    })
    const provider: OAuthProvider = {
      ...singleUseRefreshProvider(0).provider,
      refresh,
    }
    await saveUserGrant(store, 'aps', 'u1', grant())
    const source = vaultTokenSource({ store, providers: { aps: provider } })

    const refreshing = source.getToken(userRequest)
    await refreshStarted.promise
    let deletionFinished = false
    const deleting = deleteUserGrant(store, 'aps', 'u1').then(() => {
      deletionFinished = true
    })
    await delay(10)
    expect(deletionFinished).toBe(false)

    releaseRefresh.resolve()
    expect((await refreshing).token).toBe('refreshed')
    await deleting
    expect(await store.get('aec-auth:grant:aps:u1')).toBeNull()
    await expect(source.getToken(userRequest)).rejects.toMatchObject({
      name: 'TokenError',
      code: 'consent_required',
    })
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

describe('vaultTokenSource — service-account tokens', () => {
  const saRequest: TokenRequest = {
    provider: 'aps',
    subject: { type: 'service_account', id: 'SA1' },
  }

  it('N concurrent calls perform exactly one jwt-bearer mint', async () => {
    const store = memoryVaultStore()
    const { provider, serviceAccount } = singleUseRefreshProvider()
    const source = vaultTokenSource({ store, providers: { aps: provider } })

    const tokens = await Promise.all(Array.from({ length: 5 }, () => source.getToken(saRequest)))

    expect(serviceAccount).toHaveBeenCalledTimes(1)
    expect(serviceAccount).toHaveBeenCalledWith('SA1', undefined)
    expect(new Set(tokens.map((t) => t.token)).size).toBe(1)
  })

  it('serves the second call from the store cache; forceRefresh mints again', async () => {
    const store = memoryVaultStore()
    const { provider, serviceAccount } = singleUseRefreshProvider(0)
    const source = vaultTokenSource({ store, providers: { aps: provider } })

    const first = await source.getToken(saRequest)
    const second = await source.getToken(saRequest)
    expect(second.token).toBe(first.token)
    expect(serviceAccount).toHaveBeenCalledTimes(1)

    const forced = await source.getToken({ ...saRequest, forceRefresh: true })
    expect(forced.token).not.toBe(first.token)
    expect(serviceAccount).toHaveBeenCalledTimes(2)
  })

  it('two instances sharing a store serialize on the lock — one mint', async () => {
    const store = memoryVaultStore()
    const { provider, serviceAccount } = singleUseRefreshProvider()
    const a = vaultTokenSource({ store, providers: { aps: provider } })
    const b = vaultTokenSource({ store, providers: { aps: provider } })

    const [tokenA, tokenB] = await Promise.all([a.getToken(saRequest), b.getToken(saRequest)])

    expect(serviceAccount).toHaveBeenCalledTimes(1)
    expect(tokenA.token).toBe(tokenB.token)
  })

  it('a provider without serviceAccount support throws not_configured', async () => {
    const { provider } = singleUseRefreshProvider()
    const { serviceAccount: _omitted, ...withoutSa } = provider
    const source = vaultTokenSource({
      store: memoryVaultStore(),
      providers: { aps: withoutSa as OAuthProvider },
    })

    const error = await source.getToken(saRequest).catch((e: unknown) => e)
    expect(error).toBeInstanceOf(TokenError)
    expect((error as TokenError).code).toBe('not_configured')
  })

  it('never writes grant keys for service-account subjects', async () => {
    const store = memoryVaultStore()
    const writtenKeys: string[] = []
    const originalSet = store.set.bind(store)
    store.set = async (key, value, opts) => {
      writtenKeys.push(key)
      return originalSet(key, value, opts)
    }
    const { provider } = singleUseRefreshProvider(0)
    const source = vaultTokenSource({ store, providers: { aps: provider } })

    await source.getToken(saRequest)
    await source.getToken({ ...saRequest, forceRefresh: true })

    expect(writtenKeys.some((key) => key.includes('grant:'))).toBe(false)
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

  it('renews only the current owner’s lease', async () => {
    vi.useFakeTimers()
    const store = memoryVaultStore()
    const lease = (await store.acquireLock('lock', 1_000)) as string

    vi.advanceTimersByTime(750)
    expect(await store.renewLock('lock', lease, 1_000)).toBe(true)
    vi.advanceTimersByTime(750)
    expect(await store.acquireLock('lock', 1_000)).toBeNull()
    expect(await store.renewLock('lock', 'stale-owner', 1_000)).toBe(false)
  })

  it('atomically compares, replaces, and deletes values', async () => {
    const store = memoryVaultStore()

    expect(await store.compareAndSet('k', null, 'v1')).toBe(true)
    expect(await store.compareAndSet('k', null, 'v2')).toBe(false)
    expect(await store.compareAndSet('k', 'v1', 'v2')).toBe(true)
    expect(await store.compareAndSet('k', 'v2', null)).toBe(true)
    expect(await store.get('k')).toBeNull()
  })

  it('persists values without a TTL and deletes on request', async () => {
    const store = memoryVaultStore()
    await store.set('k', 'v')
    expect(await store.get('k')).toBe('v')
    await store.delete('k')
    expect(await store.get('k')).toBeNull()
  })
})

describe('forced refresh semantics', () => {
  it('a forced caller never adopts a pending cache-served run', async () => {
    const store = memoryVaultStore()
    const { provider, refresh } = singleUseRefreshProvider(0)
    await saveUserGrant(store, 'aps', 'u1', grant())
    const source = vaultTokenSource({ store, providers: { aps: provider } })

    // Warm the cache (refresh #1).
    const warmed = await source.getToken(userRequest)
    const refreshesAfterWarm = refresh.mock.calls.length

    // Hold the next token read open so a cache-served run is genuinely
    // in flight when the forced call arrives.
    const gate = deferred<void>()
    const originalGet = store.get.bind(store)
    let held = false
    store.get = async (key: string) => {
      if (!held && key.startsWith('aec-auth:token:')) {
        held = true
        await gate.promise
      }
      return originalGet(key)
    }

    const normalPending = source.getToken(userRequest)
    const forcedPending = source.getToken({ ...userRequest, forceRefresh: true })
    gate.resolve()

    const [normal, forced] = await Promise.all([normalPending, forcedPending])
    expect(normal.token).toBe(warmed.token)
    // forceRefresh means a real rotation happened — never the cached token.
    expect(refresh.mock.calls.length).toBeGreaterThan(refreshesAfterWarm)
    expect(forced.token).not.toBe(warmed.token)
  })
})
