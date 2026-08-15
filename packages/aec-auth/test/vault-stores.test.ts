import { afterEach, describe, expect, it, vi } from 'vitest'
import type { OAuthProvider } from '../src/vault'
import {
  encryptedVaultStore,
  memoryVaultStore,
  saveUserGrant,
  vaultTokenSource,
} from '../src/vault'
import { type UpstashRedisLike, upstashVaultStore } from '../src/vault-upstash'

const KEY = 'wA5jU2iyb1WBHmSA8VfLBnJdcqBOnRJUAsvUS6NDvVQ=' // openssl rand -base64 32
const OTHER_KEY = 'Fp8kQxTfV0d2mLJ9aNwYh3sB5cRuEz1gK7PiDvXoU4M='

/** In-memory stand-in honoring the exact @upstash/redis semantics the store uses. */
function fakeUpstashRedis(): UpstashRedisLike & {
  raw: Map<string, { value: string; expiresAt?: number }>
} {
  const raw = new Map<string, { value: string; expiresAt?: number }>()
  const read = (key: string): string | null => {
    const entry = raw.get(key)
    if (!entry) return null
    if (entry.expiresAt !== undefined && entry.expiresAt <= Date.now()) {
      raw.delete(key)
      return null
    }
    return entry.value
  }
  return {
    raw,
    async get(key) {
      return read(key)
    },
    async set(key, value, opts) {
      if (opts?.nx && read(key) !== null) return null
      raw.set(key, {
        value,
        expiresAt: opts?.px !== undefined ? Date.now() + opts.px : undefined,
      })
      return 'OK'
    },
    async del(key) {
      raw.delete(key)
      return 1
    },
    async eval(_script, keys, args) {
      const key = keys[0] as string
      if (read(key) === args[0]) {
        raw.delete(key)
        return 1
      }
      return 0
    },
  }
}

function fakeProvider(): OAuthProvider {
  let minted = 0
  let rotation = 0
  const issued = new Set<string>(['rt-0'])
  return {
    provider: 'aps',
    clientCredentials: async () => ({
      accessToken: { token: `at-${minted++}`, expiresAt: Date.now() + 3_600_000 },
    }),
    exchangeCode: async () => ({
      accessToken: { token: `at-${minted++}`, expiresAt: Date.now() + 3_600_000 },
      refreshToken: 'rt-0',
    }),
    refresh: async (refreshToken) => {
      if (!issued.delete(refreshToken)) throw new Error(`refresh token replayed: ${refreshToken}`)
      const next = `rt-${++rotation}`
      issued.add(next)
      return {
        accessToken: { token: `at-${minted++}`, expiresAt: Date.now() + 3_600_000 },
        refreshToken: next,
      }
    },
    authorizeUrl: () => 'https://example.test/authorize',
  }
}

afterEach(() => {
  vi.useRealTimers()
})

describe('encryptedVaultStore', () => {
  it('round-trips values while the underlying store sees only ciphertext', async () => {
    const inner = memoryVaultStore()
    const store = encryptedVaultStore(inner, { key: KEY })

    await saveUserGrant(store, 'aps', 'u1', {
      refreshToken: 'super-secret-refresh-token',
      obtainedAt: Date.now(),
    })

    const decrypted = await store.get('aec-auth:grant:aps:u1')
    expect(decrypted).toContain('super-secret-refresh-token')

    const atRest = await inner.get('aec-auth:grant:aps:u1')
    expect(atRest).not.toBeNull()
    expect(atRest).toMatch(/^enc\.v1:/)
    expect(atRest).not.toContain('super-secret-refresh-token')
  })

  it('a wrong key fails loudly, never silently returning garbage', async () => {
    const inner = memoryVaultStore()
    await encryptedVaultStore(inner, { key: KEY }).set('k', 'v')
    await expect(encryptedVaultStore(inner, { key: OTHER_KEY }).get('k')).rejects.toThrow(
      /wrong key/,
    )
  })

  it('relocated ciphertext fails: values are bound to their store key', async () => {
    const inner = memoryVaultStore()
    const store = encryptedVaultStore(inner, { key: KEY })
    await saveUserGrant(store, 'aps', 'userA', { refreshToken: 'rt-a', obtainedAt: Date.now() })

    // A compromised store copies user A's ciphertext onto user B's key.
    const stolen = (await inner.get('aec-auth:grant:aps:userA')) as string
    await inner.set('aec-auth:grant:aps:userB', stolen)

    await expect(store.get('aec-auth:grant:aps:userB')).rejects.toThrow(/relocated/)
    // The legitimate key still decrypts.
    expect(await store.get('aec-auth:grant:aps:userA')).toContain('rt-a')
  })

  it('refuses to read values written without encryption', async () => {
    const inner = memoryVaultStore()
    await inner.set('k', 'plaintext')
    await expect(encryptedVaultStore(inner, { key: KEY }).get('k')).rejects.toThrow(
      /unencrypted value/,
    )
  })

  it('rejects keys that are not 32 bytes', () => {
    expect(() => encryptedVaultStore(memoryVaultStore(), { key: 'dG9vLXNob3J0' })).toThrow(
      /32 bytes/,
    )
  })

  it('locks pass through unencrypted so lease compare-and-delete still works', async () => {
    const inner = memoryVaultStore()
    const store = encryptedVaultStore(inner, { key: KEY })
    const lease = await store.acquireLock('lock', 1_000)
    expect(lease).not.toBeNull()
    await store.releaseLock('lock', lease as string)
    expect(await store.acquireLock('lock', 1_000)).not.toBeNull()
  })
})

describe('upstashVaultStore', () => {
  it('stores values with TTL semantics', async () => {
    vi.useFakeTimers()
    const redis = fakeUpstashRedis()
    const store = upstashVaultStore({ redis })

    await store.set('k', 'v', { ttlMs: 1_000 })
    expect(await store.get('k')).toBe('v')
    vi.advanceTimersByTime(1_500)
    expect(await store.get('k')).toBeNull()
  })

  it('normalizes values from clients that auto-deserialize JSON', async () => {
    const redis = fakeUpstashRedis()
    const parsed = { refreshToken: 'rt' }
    const store = upstashVaultStore({
      redis: { ...redis, get: async () => parsed },
    })
    expect(await store.get('k')).toBe(JSON.stringify(parsed))
  })

  it('implements owner-checked locking end to end', async () => {
    vi.useFakeTimers()
    const redis = fakeUpstashRedis()
    const store = upstashVaultStore({ redis })

    const leaseA = (await store.acquireLock('lock', 1_000)) as string
    expect(leaseA).not.toBeNull()
    expect(await store.acquireLock('lock', 1_000)).toBeNull()

    // A's TTL lapses; B takes over; A's stale release must not evict B.
    vi.advanceTimersByTime(1_500)
    const leaseB = await store.acquireLock('lock', 60_000)
    expect(leaseB).not.toBeNull()
    await store.releaseLock('lock', leaseA)
    expect(await store.acquireLock('lock', 1_000)).toBeNull()

    await store.releaseLock('lock', leaseB as string)
    expect(await store.acquireLock('lock', 1_000)).not.toBeNull()
  })

  it('needs both url and token when either is given', async () => {
    await expect(upstashVaultStore({ url: 'https://x.upstash.io' }).get('k')).rejects.toThrow(
      /both url and token/,
    )
  })
})

describe('composition: vault over encrypted Upstash', () => {
  it('runs the full rotating user-refresh flow with ciphertext at rest', async () => {
    const redis = fakeUpstashRedis()
    const store = encryptedVaultStore(upstashVaultStore({ redis }), { key: KEY })
    const source = vaultTokenSource({ store, providers: { aps: fakeProvider() } })
    const subject = { type: 'user', id: 'u1' } as const

    await saveUserGrant(store, 'aps', 'u1', { refreshToken: 'rt-0', obtainedAt: Date.now() })

    const first = await source.getToken({ provider: 'aps', subject, scopes: ['data:read'] })
    const second = await source.getToken({
      provider: 'aps',
      subject,
      scopes: ['data:read'],
      forceRefresh: true,
    })
    expect(second.token).not.toBe(first.token)

    // Nothing in Redis contains a refresh token in the clear.
    for (const entry of redis.raw.values()) {
      expect(entry.value).not.toContain('rt-')
    }
  })
})
