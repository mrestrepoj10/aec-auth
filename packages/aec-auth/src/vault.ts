/**
 * `aec-auth/vault` — the self-hosted TokenSource backend.
 *
 * You bring a `VaultStore` (Redis, Postgres, Upstash, …); the vault stores
 * user grants and access tokens in it and mints tokens on demand. The hard
 * part it solves: APS refresh tokens are single-use, so a refresh must run
 * exactly once across every process that wants the token. Refreshes are
 * single-flighted in-process (promise dedupe) and cross-process (store lock),
 * and the rotated refresh token is persisted before the access token is
 * released to callers.
 */
import {
  type AccessToken,
  isExpired,
  type Provider,
  requestKey,
  subjectKey,
  TokenError,
  type TokenRequest,
  type TokenSource,
} from './index'
import type { OAuthProvider, OAuthTokenResult } from './internal/oauth'

export type {
  AuthorizeUrlParams,
  ExchangeCodeParams,
  OAuthProvider,
  OAuthTokenResult,
} from './internal/oauth'
export { apsOAuth } from './internal/oauth'

/**
 * Minimal persistence contract the vault runs on. Implement it over Redis,
 * Postgres, Upstash — anything with atomic set-if-not-exists for the lock.
 */
export interface VaultStore {
  get(key: string): Promise<string | null>
  set(key: string, value: string, opts?: { ttlMs?: number }): Promise<void>
  delete(key: string): Promise<void>
  /**
   * Atomic set-if-not-exists. Resolves an opaque lease when this caller now
   * holds the lock, `null` when someone else does. The lease is what makes
   * release safe: a holder whose lock TTL expired cannot delete the lock a
   * later caller acquired (Redis: `SET key lease NX PX ttl`).
   */
  acquireLock(key: string, ttlMs: number): Promise<string | null>
  /**
   * Extend a lease only while `lease` still owns it. Returns false after
   * ownership is lost (Redis: compare `GET`, then `PEXPIRE`, in one script).
   */
  renewLock(key: string, lease: string, ttlMs: number): Promise<boolean>
  /**
   * Release the lock only if `lease` still owns it — compare-and-delete
   * (Redis: a `GET`/`DEL` Lua script), never an unconditional delete.
   */
  releaseLock(key: string, lease: string): Promise<void>
  /** Atomically replace `expected` with `value`, or report that it changed. */
  compareAndSet(key: string, expected: string | null, value: string | null): Promise<boolean>
}

/** In-memory `VaultStore` for development and tests. Lazy TTL expiry. */
export function memoryVaultStore(): VaultStore {
  const entries = new Map<string, { value: string; expiresAt?: number }>()
  const read = (key: string): string | null => {
    const entry = entries.get(key)
    if (!entry) return null
    if (entry.expiresAt !== undefined && entry.expiresAt <= Date.now()) {
      entries.delete(key)
      return null
    }
    return entry.value
  }
  return {
    async get(key) {
      return read(key)
    },
    async set(key, value, opts) {
      entries.set(key, {
        value,
        expiresAt: opts?.ttlMs !== undefined ? Date.now() + opts.ttlMs : undefined,
      })
    },
    async delete(key) {
      entries.delete(key)
    },
    async acquireLock(key, ttlMs) {
      if (read(key) !== null) return null
      const lease = crypto.randomUUID()
      entries.set(key, { value: lease, expiresAt: Date.now() + ttlMs })
      return lease
    },
    async renewLock(key, lease, ttlMs) {
      if (read(key) !== lease) return false
      entries.set(key, { value: lease, expiresAt: Date.now() + ttlMs })
      return true
    },
    async releaseLock(key, lease) {
      if (read(key) === lease) entries.delete(key)
    },
    async compareAndSet(key, expected, value) {
      if (read(key) !== expected) return false
      if (value === null) entries.delete(key)
      else entries.set(key, { value })
      return true
    },
  }
}

const ENC_PREFIX = 'enc.v1:'

function decodeKey(key: string): Uint8Array {
  if (/^[0-9a-fA-F]{64}$/.test(key)) {
    const bytes = new Uint8Array(32)
    for (let i = 0; i < 32; i++) bytes[i] = Number.parseInt(key.slice(i * 2, i * 2 + 2), 16)
    return bytes
  }
  const raw = atob(key.replace(/-/g, '+').replace(/_/g, '/'))
  const bytes = Uint8Array.from(raw, (ch) => ch.charCodeAt(0))
  if (bytes.length !== 32) {
    throw new Error(
      `encryptedVaultStore key must be 32 bytes (base64 or hex); got ${bytes.length} bytes. Generate one with: openssl rand -base64 32`,
    )
  }
  return bytes
}

function toBase64(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary)
}

function fromBase64(text: string): Uint8Array {
  return Uint8Array.from(atob(text), (ch) => ch.charCodeAt(0))
}

/**
 * Wraps any `VaultStore` with AES-256-GCM encryption at rest (WebCrypto, so
 * it runs everywhere the core does). Values — grants with their refresh
 * tokens, cached access tokens — are stored as `enc.v1:` + base64(iv ||
 * ciphertext); lock leases pass through untouched (they are random values,
 * not secrets). `key` is a 32-byte secret, base64 or hex encoded
 * (`openssl rand -base64 32`); losing it orphans every stored grant, and a
 * wrong key surfaces as a decryption error, never as silent plaintext.
 */
export function encryptedVaultStore(store: VaultStore, options: { key: string }): VaultStore {
  const keyBytes = decodeKey(options.key)
  let cryptoKey: Promise<CryptoKey> | undefined
  const getKey = (): Promise<CryptoKey> => {
    cryptoKey ??= crypto.subtle.importKey('raw', keyBytes as BufferSource, 'AES-GCM', false, [
      'encrypt',
      'decrypt',
    ])
    return cryptoKey
  }

  // The store key is bound as AES-GCM additionalData so ciphertext cannot be
  // relocated: copying user A's encrypted grant onto user B's key fails
  // decryption instead of letting B refresh with A's grant.
  const encrypt = async (storeKey: string, plaintext: string): Promise<string> => {
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(storeKey) },
      await getKey(),
      new TextEncoder().encode(plaintext),
    )
    const combined = new Uint8Array(iv.length + ciphertext.byteLength)
    combined.set(iv)
    combined.set(new Uint8Array(ciphertext), iv.length)
    return ENC_PREFIX + toBase64(combined)
  }

  const decrypt = async (storeKey: string, stored: string): Promise<string> => {
    if (!stored.startsWith(ENC_PREFIX)) {
      throw new Error(
        'encryptedVaultStore found an unencrypted value; was this store previously used without encryption?',
      )
    }
    const combined = fromBase64(stored.slice(ENC_PREFIX.length))
    try {
      const plaintext = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: combined.slice(0, 12) as BufferSource,
          additionalData: new TextEncoder().encode(storeKey),
        },
        await getKey(),
        combined.slice(12) as BufferSource,
      )
      return new TextDecoder().decode(plaintext)
    } catch {
      throw new Error('encryptedVaultStore failed to decrypt; wrong key or relocated value?')
    }
  }

  return {
    async get(key) {
      const stored = await store.get(key)
      return stored === null ? null : decrypt(key, stored)
    },
    async set(key, value, opts) {
      await store.set(key, await encrypt(key, value), opts)
    },
    delete: (key) => store.delete(key),
    acquireLock: (key, ttlMs) => store.acquireLock(key, ttlMs),
    renewLock: (key, lease, ttlMs) => store.renewLock(key, lease, ttlMs),
    releaseLock: (key, lease) => store.releaseLock(key, lease),
    async compareAndSet(key, expected, value) {
      const encrypted = value === null ? null : await encrypt(key, value)
      for (;;) {
        const current = await store.get(key)
        const plaintext = current === null ? null : await decrypt(key, current)
        if (plaintext !== expected) return false
        if (await store.compareAndSet(key, current, encrypted)) return true
      }
    },
  }
}

/** A user's stored refresh grant for one provider. */
export interface UserGrant {
  refreshToken: string
  scopes?: string[]
  /** Epoch milliseconds when the grant (or its latest rotation) was obtained. */
  obtainedAt: number
}

interface StoredUserGrant extends UserGrant {
  /** Changes on consent and every rotation; cached tokens bind to this value. */
  generation: string
}

interface StoredAccessToken {
  accessToken: AccessToken
  generation: string
  grantGeneration?: string
}

const PREFIX = 'aec-auth:'
const LOCK_TTL_MS = 10_000
const LOCK_RENEW_INTERVAL_MS = Math.floor(LOCK_TTL_MS / 3)
const WAIT_TIMEOUT_MS = 2_000
const WAIT_INITIAL_MS = 25
const WAIT_MAX_MS = 250

function tokenKey(request: TokenRequest): string {
  return `${PREFIX}token:${requestKey(request)}`
}

function grantKey(provider: Provider, userId: string): string {
  return `${PREFIX}grant:${provider}:${userId}`
}

function subjectLockKey(provider: Provider, subject: TokenRequest['subject']): string {
  return `${PREFIX}lock:${provider}:${subjectKey(subject)}`
}

function lockKey(request: TokenRequest): string {
  return subjectLockKey(request.provider, request.subject)
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

function leaseError(provider: Provider, cause?: unknown): TokenError {
  return new TokenError(
    'provider_error',
    provider,
    `lost ownership of the ${provider} refresh lease`,
    cause === undefined ? undefined : { cause },
  )
}

function maintainLease(store: VaultStore, key: string, lease: string, provider: Provider) {
  let stopped = false
  let timer: ReturnType<typeof setTimeout> | undefined
  let lost: TokenError | undefined
  let renewal = Promise.resolve()

  const renew = async (): Promise<void> => {
    try {
      if (!(await store.renewLock(key, lease, LOCK_TTL_MS))) lost = leaseError(provider)
    } catch (cause) {
      lost = leaseError(provider, cause)
    }
  }

  const schedule = (): void => {
    timer = setTimeout(() => {
      renewal = renew().finally(() => {
        if (!stopped && !lost) schedule()
      })
    }, LOCK_RENEW_INTERVAL_MS)
  }
  schedule()

  return {
    async assertOwned(): Promise<void> {
      if (lost) throw lost
      await renew()
      if (lost) throw lost
    },
    async stop(): Promise<void> {
      stopped = true
      if (timer !== undefined) clearTimeout(timer)
      await renewal
    },
  }
}

async function waitForLease(store: VaultStore, key: string): Promise<string> {
  let delay = WAIT_INITIAL_MS
  for (;;) {
    const lease = await store.acquireLock(key, LOCK_TTL_MS)
    if (lease !== null) return lease
    await sleep(delay)
    delay = Math.min(delay * 2, WAIT_MAX_MS)
  }
}

async function readStoredGrant(
  store: VaultStore,
  provider: Provider,
  userId: string,
): Promise<{ raw: string; grant: StoredUserGrant } | null> {
  const raw = await store.get(grantKey(provider, userId))
  if (raw === null) return null
  try {
    const parsed = JSON.parse(raw) as UserGrant & { generation?: string }
    return {
      raw,
      grant: { ...parsed, generation: parsed.generation ?? 'legacy' },
    }
  } catch {
    return null
  }
}

/**
 * Store a user's refresh grant — call after `exchangeCode` completes the
 * consent flow. Overwrites any previous grant for the provider + user.
 */
export async function saveUserGrant(
  store: VaultStore,
  provider: Provider,
  userId: string,
  grant: UserGrant,
): Promise<void> {
  const key = subjectLockKey(provider, { type: 'user', id: userId })
  const lease = await waitForLease(store, key)
  const guard = maintainLease(store, key, lease, provider)
  try {
    await guard.assertOwned()
    await store.set(
      grantKey(provider, userId),
      JSON.stringify({ ...grant, generation: crypto.randomUUID() }),
    )
  } finally {
    await guard.stop()
    await store.releaseLock(key, lease)
  }
}

/**
 * Remove a user's stored grant. Deletion serializes with refresh and makes
 * every cached token from the deleted grant ineligible for reuse.
 */
export async function deleteUserGrant(
  store: VaultStore,
  provider: Provider,
  userId: string,
): Promise<void> {
  const key = subjectLockKey(provider, { type: 'user', id: userId })
  const lease = await waitForLease(store, key)
  const guard = maintainLease(store, key, lease, provider)
  try {
    const current = await store.get(grantKey(provider, userId))
    if (current === null) return
    await guard.assertOwned()
    if (!(await store.compareAndSet(grantKey(provider, userId), current, null))) {
      throw leaseError(provider)
    }
  } finally {
    await guard.stop()
    await store.releaseLock(key, lease)
  }
}

/**
 * Self-hosted `TokenSource` over a `VaultStore`.
 *
 * - `app` subjects mint via `client_credentials`, cached in the store.
 * - `user` subjects refresh from the stored grant; no grant throws
 *   `consent_required`.
 * - Refreshes are single-flight in-process and across processes via the
 *   store lock; losers wait for the winner's token instead of racing the
 *   single-use refresh token.
 */
export function vaultTokenSource(options: {
  store: VaultStore
  providers: Partial<Record<Provider, OAuthProvider>>
}): TokenSource {
  const { store, providers } = options
  const inflight = new Map<string, Promise<AccessToken>>()

  const readToken = async (key: string): Promise<StoredAccessToken | null> => {
    const raw = await store.get(key)
    if (raw === null) return null
    try {
      const parsed = JSON.parse(raw) as StoredAccessToken
      return parsed.accessToken && parsed.generation ? parsed : null
    } catch {
      return null
    }
  }

  const readValidToken = async (
    request: TokenRequest,
    key: string,
  ): Promise<StoredAccessToken | null> => {
    const stored = await readToken(key)
    if (!stored || isExpired(stored.accessToken)) return null
    if (request.subject.type === 'app') return stored
    const currentGrant = await readStoredGrant(store, request.provider, request.subject.id)
    return currentGrant?.grant.generation === stored.grantGeneration ? stored : null
  }

  const mintUnderLock = async (
    oauth: OAuthProvider,
    request: TokenRequest,
    assertLease: () => Promise<void>,
  ): Promise<{ result: OAuthTokenResult; grantGeneration?: string }> => {
    if (request.subject.type === 'app') {
      return { result: await oauth.clientCredentials(request.scopes) }
    }
    const userId = request.subject.id
    // Re-read the grant under the lock: a concurrent refresh rotates it.
    const stored = await readStoredGrant(store, request.provider, userId)
    if (!stored) {
      throw new TokenError(
        'consent_required',
        request.provider,
        `no stored ${request.provider} grant for user ${userId}`,
      )
    }
    const { grant, raw } = stored
    const result = await oauth.refresh(grant.refreshToken, request.scopes ?? grant.scopes)
    // Persist the rotated refresh token BEFORE the access token is written or
    // returned: a crash after this write loses only an access token; a crash
    // before it would lose the grant (the old refresh token is already dead).
    const nextGrant: StoredUserGrant = {
      refreshToken: result.refreshToken ?? grant.refreshToken,
      scopes: grant.scopes,
      obtainedAt: Date.now(),
      generation: crypto.randomUUID(),
    }
    await assertLease()
    if (
      !(await store.compareAndSet(
        grantKey(request.provider, userId),
        raw,
        JSON.stringify(nextGrant),
      ))
    ) {
      throw new TokenError(
        'grant_invalid',
        request.provider,
        `stored ${request.provider} grant changed during refresh for user ${userId}`,
      )
    }
    return { result, grantGeneration: nextGrant.generation }
  }

  const acquireAndMint = async (
    oauth: OAuthProvider,
    request: TokenRequest,
  ): Promise<AccessToken> => {
    if (request.subject.type === 'user') {
      const grant = await readStoredGrant(store, request.provider, request.subject.id)
      if (!grant) {
        throw new TokenError(
          'consent_required',
          request.provider,
          `no stored ${request.provider} grant for user ${request.subject.id}`,
        )
      }
    }
    const lock = lockKey(request)
    const key = tokenKey(request)
    const baselineGeneration = request.forceRefresh ? (await readToken(key))?.generation : undefined
    const deadline = Date.now() + WAIT_TIMEOUT_MS
    let delay = WAIT_INITIAL_MS
    for (;;) {
      const lease = await store.acquireLock(lock, LOCK_TTL_MS)
      if (lease !== null) {
        const guard = maintainLease(store, lock, lease, request.provider)
        try {
          // Re-read under the lock: another process may have refreshed while
          // we waited, in which case its token is the one to use.
          if (!request.forceRefresh) {
            const current = await readValidToken(request, key)
            if (current) return current.accessToken
          }
          const minted = await mintUnderLock(oauth, request, guard.assertOwned)
          const stored: StoredAccessToken = {
            accessToken: minted.result.accessToken,
            generation: crypto.randomUUID(),
            grantGeneration: minted.grantGeneration,
          }
          await guard.assertOwned()
          const ttlMs = stored.accessToken.expiresAt - Date.now()
          await store.set(key, JSON.stringify(stored), ttlMs > 0 ? { ttlMs } : undefined)
          await guard.assertOwned()
          return stored.accessToken
        } finally {
          await guard.stop()
          await store.releaseLock(lock, lease)
        }
      }
      // Another process holds the refresh lock. Poll for its token rather
      // than racing the (single-use) refresh; give up with a clear error.
      if (Date.now() >= deadline) {
        throw new TokenError(
          'provider_error',
          request.provider,
          `timed out after ${WAIT_TIMEOUT_MS}ms waiting for a concurrent ${request.provider} token refresh`,
        )
      }
      await sleep(delay)
      delay = Math.min(delay * 2, WAIT_MAX_MS)
      const fromWinner = await readValidToken(request, key)
      if (fromWinner && (!request.forceRefresh || fromWinner.generation !== baselineGeneration)) {
        return fromWinner.accessToken
      }
    }
  }

  return {
    async getToken(request) {
      const oauth = providers[request.provider]
      if (!oauth) {
        throw new TokenError(
          'not_configured',
          request.provider,
          `no OAuth provider configured for ${request.provider}`,
        )
      }
      const key = requestKey(request)
      const pending = inflight.get(key)
      if (pending) return pending
      const run = (async () => {
        if (!request.forceRefresh) {
          const cached = await readValidToken(request, tokenKey(request))
          if (cached) return cached.accessToken
        }
        return acquireAndMint(oauth, request)
      })().finally(() => {
        if (inflight.get(key) === run) inflight.delete(key)
      })
      inflight.set(key, run)
      return run
    },
  }
}
