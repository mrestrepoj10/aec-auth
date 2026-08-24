/**
 * Secure Service Account administration (`aec-auth/ssa`): typed management of
 * service accounts and their signing keys over any {@link TokenSource}, so
 * onboarding and key rotation don't require a web tool. Every endpoint
 * accepts only 2-legged tokens, so all requests use an `app` subject
 * internally; the token needs the `application:service_account*` scopes
 * (see `apsScopes.ssaAdmin`).
 *
 * Key rotation recipe (max 3 keys per account): `keys.create` → update the
 * `ServiceAccountKeyResolver`'s backing store to the new key → verify a mint
 * succeeds → `keys.delete(oldKid)`.
 */
import { APS_BASE_URL, authHeaders, type TokenSource } from './index'
import { isRetryableBody, RATE_LIMIT_RETRIES, rateLimitDelayMs, sleep } from './internal/http'

/** A service account, as returned by the management endpoints. */
export interface ServiceAccountDetails {
  serviceAccountId: string
  /** `<name>@<clientId>.adskserviceaccount.autodesk.com` — the address an ACC admin invites as a member. */
  email: string
  createdBy?: string
  /** `DEACTIVATED` happens automatically after 12 idle months; re-enable via `setStatus`. */
  status?: 'ENABLED' | 'DISABLED' | 'DEACTIVATED'
  createdAt?: string
  accessedAt?: string
  expiresAt?: string
}

/** Metadata for a service account's signing key (the private key is never listed). */
export interface ServiceAccountKeyDetails {
  kid: string
  status?: 'ENABLED' | 'DISABLED'
  createdAt?: string
  accessedAt?: string
}

const READ_SCOPES = [
  'application:service_account:read',
  'application:service_account_key:read',
] as const
const ACCOUNT_WRITE_SCOPES = ['application:service_account:write'] as const
const KEY_WRITE_SCOPES = ['application:service_account_key:write'] as const

const ACCOUNTS_PATH = '/authentication/v2/service-accounts'

/**
 * Typed SSA management client. All endpoints are rate-limited to 10
 * requests/minute per app; 429s are retried honoring `Retry-After`, and 401s
 * once with a force-refreshed token.
 */
export function createSsaAdminClient(options: {
  tokens: TokenSource
  /** Override the API origin. Defaults to {@link APS_BASE_URL}. */
  baseUrl?: string
  /** Injectable `fetch` for tests and mocks. Defaults to the global. */
  fetch?: typeof fetch
}): {
  accounts: {
    /** `POST /authentication/v2/service-accounts` — create an account (max 10 per app). */
    create(params: {
      name: string
      firstName: string
      lastName: string
    }): Promise<{ serviceAccountId: string; email: string }>
    /** `GET /authentication/v2/service-accounts` — all of the app's accounts. */
    list(): Promise<ServiceAccountDetails[]>
    /** `GET /authentication/v2/service-accounts/:id` — one account. */
    get(serviceAccountId: string): Promise<ServiceAccountDetails>
    /** `PATCH /authentication/v2/service-accounts/:id` — enable or disable (disabling rejects its keys' assertions). */
    setStatus(
      serviceAccountId: string,
      status: 'ENABLED' | 'DISABLED',
    ): Promise<ServiceAccountDetails>
    /** `DELETE /authentication/v2/service-accounts/:id` (204) — deletes the account and all its keys. */
    delete(serviceAccountId: string): Promise<void>
  }
  keys: {
    /**
     * `POST /authentication/v2/service-accounts/:id/keys` — mint a signing key
     * (max 3 per account). The returned `privateKey` PEM is shown exactly
     * once — persist it immediately (e.g. into an encryptedVaultStore-backed
     * secret).
     */
    create(serviceAccountId: string): Promise<{ kid: string; privateKey: string }>
    /** `GET /authentication/v2/service-accounts/:id/keys` — key metadata only. */
    list(serviceAccountId: string): Promise<ServiceAccountKeyDetails[]>
    /** `PATCH /authentication/v2/service-accounts/:id/keys/:kid` (204). */
    setStatus(
      serviceAccountId: string,
      keyId: string,
      status: 'ENABLED' | 'DISABLED',
    ): Promise<void>
    /** `DELETE /authentication/v2/service-accounts/:id/keys/:kid` (204). */
    delete(serviceAccountId: string, keyId: string): Promise<void>
  }
} {
  const baseUrl = options.baseUrl ?? APS_BASE_URL
  const fetchImpl = options.fetch ?? globalThis.fetch.bind(globalThis)

  async function send(
    path: string,
    init: RequestInit | undefined,
    scopes: readonly string[],
    forceRefresh: boolean,
  ): Promise<Response> {
    const token = await options.tokens.getToken({
      provider: 'aps',
      subject: { type: 'app' },
      scopes,
      ...(forceRefresh ? { forceRefresh: true } : {}),
    })
    const headers = new Headers(init?.headers)
    headers.set('Authorization', authHeaders(token).Authorization)
    return fetchImpl(`${baseUrl}${path}`, { ...init, headers })
  }

  async function request(
    path: string,
    init: RequestInit | undefined,
    scopes: readonly string[],
    limitHint?: string,
  ): Promise<Response> {
    let response = await send(path, init, scopes, false)
    if (response.status === 401) response = await send(path, init, scopes, true)
    for (let attempt = 0; response.status === 429 && attempt < RATE_LIMIT_RETRIES; attempt += 1) {
      if (!isRetryableBody(init?.body)) break
      await sleep(rateLimitDelayMs(response, attempt))
      response = await send(path, init, scopes, false)
    }
    if (!response.ok) {
      const body = await response.text().catch(() => '')
      const hint = response.status === 403 && limitHint ? ` (${limitHint})` : ''
      throw new Error(
        `APS SSA request ${path} failed with ${response.status} ${response.statusText}` +
          hint +
          (body ? `: ${body}` : ''),
      )
    }
    return response
  }

  function jsonInit(body: unknown, method: string): RequestInit {
    return {
      method,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }
  }

  const accountPath = (serviceAccountId: string): string =>
    `${ACCOUNTS_PATH}/${encodeURIComponent(serviceAccountId)}`

  return {
    accounts: {
      async create(params) {
        const response = await request(
          ACCOUNTS_PATH,
          jsonInit(params, 'POST'),
          ACCOUNT_WRITE_SCOPES,
          'the app may already be at its limit of 10 service accounts',
        )
        return (await response.json()) as { serviceAccountId: string; email: string }
      },
      async list() {
        const response = await request(ACCOUNTS_PATH, undefined, READ_SCOPES)
        const page = (await response.json()) as { serviceAccounts?: ServiceAccountDetails[] }
        return page.serviceAccounts ?? []
      },
      async get(serviceAccountId) {
        const response = await request(accountPath(serviceAccountId), undefined, READ_SCOPES)
        return (await response.json()) as ServiceAccountDetails
      },
      async setStatus(serviceAccountId, status) {
        const response = await request(
          accountPath(serviceAccountId),
          jsonInit({ status }, 'PATCH'),
          ACCOUNT_WRITE_SCOPES,
        )
        return (await response.json()) as ServiceAccountDetails
      },
      async delete(serviceAccountId) {
        await request(accountPath(serviceAccountId), { method: 'DELETE' }, ACCOUNT_WRITE_SCOPES)
      },
    },
    keys: {
      async create(serviceAccountId) {
        const response = await request(
          `${accountPath(serviceAccountId)}/keys`,
          { method: 'POST' },
          KEY_WRITE_SCOPES,
          'the account may already be at its limit of 3 keys — rotate by deleting an old key first',
        )
        return (await response.json()) as { kid: string; privateKey: string }
      },
      async list(serviceAccountId) {
        const response = await request(
          `${accountPath(serviceAccountId)}/keys`,
          undefined,
          READ_SCOPES,
        )
        const page = (await response.json()) as { keys?: ServiceAccountKeyDetails[] }
        return page.keys ?? []
      },
      async setStatus(serviceAccountId, keyId, status) {
        await request(
          `${accountPath(serviceAccountId)}/keys/${encodeURIComponent(keyId)}`,
          jsonInit({ status }, 'PATCH'),
          KEY_WRITE_SCOPES,
        )
      },
      async delete(serviceAccountId, keyId) {
        await request(
          `${accountPath(serviceAccountId)}/keys/${encodeURIComponent(keyId)}`,
          { method: 'DELETE' },
          KEY_WRITE_SCOPES,
        )
      },
    },
  }
}
