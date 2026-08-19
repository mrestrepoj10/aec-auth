/**
 * Upstash Redis `VaultStore` (`aec-auth/vault/upstash`) — the reference
 * production store. REST-based, so it runs everywhere the core does (Node,
 * edge, workers). Locking follows the canonical Redis pattern: acquire is
 * `SET key lease NX PX ttl`, release is a compare-and-delete Lua script, so
 * a holder whose TTL expired can never delete a later caller's lock.
 *
 * `@upstash/redis` is an optional peer, loaded lazily. Compose with
 * `encryptedVaultStore` for encryption at rest:
 *
 *   const store = encryptedVaultStore(upstashVaultStore(), { key: process.env.VAULT_KEY! })
 */
import type { VaultStore } from './vault'

/**
 * The subset of `@upstash/redis` the store uses. Accepts a real `Redis`
 * instance (pass one with `automaticDeserialization: false`) or any
 * compatible implementation in tests.
 */
export interface UpstashRedisLike {
  get(key: string): Promise<unknown>
  set(key: string, value: string, opts?: { nx?: true; px?: number }): Promise<unknown>
  del(key: string): Promise<unknown>
  eval(script: string, keys: string[], args: string[]): Promise<unknown>
}

const RELEASE_SCRIPT = `
if redis.call("GET", KEYS[1]) == ARGV[1] then
  return redis.call("DEL", KEYS[1])
else
  return 0
end
`

const RENEW_SCRIPT = `
if redis.call("GET", KEYS[1]) == ARGV[1] then
  return redis.call("PEXPIRE", KEYS[1], ARGV[2])
else
  return 0
end
`

const COMPARE_AND_SET_SCRIPT = `
local current = redis.call("GET", KEYS[1])
local expected_matches =
  (ARGV[1] == "0" and current == false) or
  (ARGV[1] == "1" and current == ARGV[2])
if not expected_matches then
  return 0
end
if ARGV[3] == "0" then
  redis.call("DEL", KEYS[1])
else
  redis.call("SET", KEYS[1], ARGV[4])
end
return 1
`

/**
 * Creates a `VaultStore` over Upstash Redis. With no options it reads
 * `UPSTASH_REDIS_REST_URL` / `UPSTASH_REDIS_REST_TOKEN` from the
 * environment; pass `url`/`token` explicitly, or `redis` to reuse a client.
 */
export function upstashVaultStore(options?: {
  url?: string
  token?: string
  redis?: UpstashRedisLike
}): VaultStore {
  let client: Promise<UpstashRedisLike> | undefined

  const getClient = (): Promise<UpstashRedisLike> => {
    client ??= (async () => {
      if (options?.redis) return options.redis
      let mod: typeof import('@upstash/redis')
      try {
        mod = await import('@upstash/redis')
      } catch (cause) {
        throw new Error(
          'aec-auth/vault/upstash requires the optional peer @upstash/redis — install it with: pnpm add @upstash/redis',
          { cause },
        )
      }
      // Values are stored as opaque strings (possibly encrypted); the SDK's
      // automatic JSON deserialization must stay off so get() returns them
      // byte-for-byte.
      if (options?.url !== undefined || options?.token !== undefined) {
        if (options.url === undefined || options.token === undefined) {
          throw new Error('aec-auth/vault/upstash needs both url and token when either is given')
        }
        return new mod.Redis({
          url: options.url,
          token: options.token,
          automaticDeserialization: false,
        })
      }
      return mod.Redis.fromEnv({ automaticDeserialization: false })
    })()
    return client
  }

  const asString = (value: unknown): string | null => {
    if (value === null || value === undefined) return null
    return typeof value === 'string' ? value : JSON.stringify(value)
  }

  return {
    async get(key) {
      const redis = await getClient()
      return asString(await redis.get(key))
    },
    async set(key, value, opts) {
      const redis = await getClient()
      await redis.set(key, value, opts?.ttlMs !== undefined ? { px: opts.ttlMs } : undefined)
    },
    async delete(key) {
      const redis = await getClient()
      await redis.del(key)
    },
    async acquireLock(key, ttlMs) {
      const redis = await getClient()
      const lease = crypto.randomUUID()
      const result = await redis.set(key, lease, { nx: true, px: ttlMs })
      return result === 'OK' ? lease : null
    },
    async renewLock(key, lease, ttlMs) {
      const redis = await getClient()
      return Number(await redis.eval(RENEW_SCRIPT, [key], [lease, String(ttlMs)])) === 1
    },
    async releaseLock(key, lease) {
      const redis = await getClient()
      await redis.eval(RELEASE_SCRIPT, [key], [lease])
    },
    async compareAndSet(key, expected, value) {
      const redis = await getClient()
      const result = await redis.eval(
        COMPARE_AND_SET_SCRIPT,
        [key],
        [expected === null ? '0' : '1', expected ?? '', value === null ? '0' : '1', value ?? ''],
      )
      return Number(result) === 1
    },
  }
}
