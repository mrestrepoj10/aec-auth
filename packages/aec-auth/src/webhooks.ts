/**
 * APS Webhooks helpers (`aec-auth/webhooks`): callback signature verification
 * plus a typed hooks/secret-token client over any {@link TokenSource} — so
 * consumers can register hooks and verify deliveries instead of polling.
 * Zero-dependency and runtime-agnostic like the rest of the package.
 */
import { APS_BASE_URL, authHeaders, type TokenSource, type TokenSubject } from './index'
import { isRetryableBody, RATE_LIMIT_RETRIES, rateLimitDelayMs, sleep } from './internal/http'

/**
 * Verifies the `x-adsk-signature` header the APS Webhooks service sends when
 * a secret token is configured: `sha1hash=` + hex(HMAC-SHA1(secret, body)).
 * Pass the RAW request body (string or bytes) exactly as received — verify
 * before JSON parsing; any re-serialization breaks the digest.
 */
export async function verifyWebhookSignature(options: {
  payload: string | Uint8Array
  signature: string | null
  secret: string
}): Promise<boolean> {
  const { payload, signature, secret } = options
  if (signature === null || !signature.startsWith('sha1hash=')) return false
  const hex = signature.slice('sha1hash='.length)
  if (hex.length === 0 || hex.length % 2 !== 0 || /[^0-9a-fA-F]/.test(hex)) return false
  const expected = new Uint8Array(hex.length / 2)
  for (let i = 0; i < expected.length; i++) {
    expected[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['verify'],
  )
  const body = typeof payload === 'string' ? new TextEncoder().encode(payload) : payload
  // crypto.subtle.verify is the constant-time comparison.
  return crypto.subtle.verify('HMAC', key, expected as BufferSource, body as BufferSource)
}

/** `x-ads-region` values the Webhooks service accepts. */
export type WebhooksRegion = 'US' | 'EMEA' | 'AUS' | 'GBR' | 'JPN' | 'DEU' | 'CAN' | 'IND'

/** A registered webhook, as returned by the list endpoints. */
export interface WebhookRecord {
  hookId: string
  system: string
  event: string
  status: 'active' | 'inactive'
  callbackUrl: string
  scope: Record<string, string>
  createdBy?: string
  createdDate?: string
  autoReactivateHook?: boolean
  hookExpiry?: string | null
  [key: string]: unknown
}

/** Parameters for {@link WebhooksClient} `hooks.create`. */
export interface CreateHookParams {
  /** Webhook system, e.g. `data`, `adsk.construction.issues`. */
  system: string
  /** Event within the system, e.g. `dm.version.added`. */
  event: string
  callbackUrl: string
  /** What to watch, e.g. `{ folder: 'urn:adsk.wipprod:fs.folder:…' }`. */
  scope: Record<string, string>
  /** Opaque payload (< 1KB) echoed back in every callback. */
  hookAttribute?: Record<string, unknown>
  /** JsonPath filter applied to events before delivery. */
  filter?: string
  hubId?: string
  projectId?: string
  tenant?: string
  autoReactivateHook?: boolean
  /** ISO8601 expiry for the hook. */
  hookExpiry?: string
}

/** The client returned by {@link createWebhooksClient}. */
export interface WebhooksClient {
  hooks: {
    /** `POST /webhooks/v1/systems/:system/events/:event/hooks` → hookId parsed from the Location header. */
    create(params: CreateHookParams): Promise<{ hookId: string }>
    /** `GET /webhooks/v1/systems/:system/events/:event/hooks`, iterated across pageState pages. */
    list(system: string, event: string): AsyncGenerator<WebhookRecord, void, undefined>
    /** `GET /webhooks/v1/app/hooks` — every hook of the app. APS accepts 2-legged tokens only here; use an `app` subject. */
    listApp(): AsyncGenerator<WebhookRecord, void, undefined>
    /** `DELETE /webhooks/v1/systems/:system/events/:event/hooks/:hookId` (204). */
    delete(system: string, event: string, hookId: string): Promise<void>
  }
  secretToken: {
    /** `POST /webhooks/v1/tokens` — set the signing secret (400 if one exists). */
    set(token: string): Promise<void>
    /** `PUT /webhooks/v1/tokens/@me` — rotate the signing secret. */
    update(token: string): Promise<void>
    /** `DELETE /webhooks/v1/tokens/@me`. */
    remove(): Promise<void>
  }
}

const READ_SCOPES = ['data:read'] as const
const WRITE_SCOPES = ['data:read', 'data:write'] as const

/**
 * Extracts the `pageState` from a `links.next` value. The docs' `next` is not
 * reliably resolvable as a path, so the original path is re-requested with
 * `?pageState=…` instead. A `next` without a query string is treated as the
 * state itself.
 */
function extractPageState(next: string | null | undefined): string | null {
  if (!next) return null
  if (!next.includes('?')) return next
  return new URL(next, APS_BASE_URL).searchParams.get('pageState')
}

/**
 * Typed APS Webhooks client over a {@link TokenSource}. Mirrors
 * `createApsClient`'s behavior (401 retried once with a force-refreshed
 * token, 429 retried honoring `Retry-After`) but owns its token scopes:
 * reads request `data:read`, writes `data:read data:write`.
 *
 * SSA composes: pass `subject: { type: 'service_account', id }` and hooks are
 * created as that account (its folder permissions govern what it may hook).
 * `hooks.listApp` requires `subject: { type: 'app' }`.
 */
export function createWebhooksClient(options: {
  tokens: TokenSource
  subject: TokenSubject
  /** `x-ads-region` for every request. Defaults to APS's default (US). */
  region?: WebhooksRegion
  /** Override the API origin. Defaults to {@link APS_BASE_URL}. */
  baseUrl?: string
  /** Injectable `fetch` for tests and mocks. Defaults to the global. */
  fetch?: typeof fetch
}): WebhooksClient {
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
      subject: options.subject,
      scopes,
      ...(forceRefresh ? { forceRefresh: true } : {}),
    })
    const headers = new Headers(init?.headers)
    headers.set('Authorization', authHeaders(token).Authorization)
    if (options.region !== undefined) headers.set('x-ads-region', options.region)
    return fetchImpl(`${baseUrl}${path}`, { ...init, headers })
  }

  async function request(
    path: string,
    init: RequestInit | undefined,
    scopes: readonly string[],
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
      const conflict =
        response.status === 409 ? ' (a hook for this event and scope already exists)' : ''
      throw new Error(
        `APS webhooks request ${path} failed with ${response.status} ${response.statusText}` +
          conflict +
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

  async function* listHooks(path: string): AsyncGenerator<WebhookRecord, void, undefined> {
    let pageState: string | null = null
    do {
      const pagedPath: string = pageState
        ? `${path}?pageState=${encodeURIComponent(pageState)}`
        : path
      const response = await request(pagedPath, undefined, READ_SCOPES)
      if (response.status === 204) return
      const page = (await response.json()) as {
        links?: { next?: string | null }
        data?: WebhookRecord[]
      }
      yield* page.data ?? []
      pageState = extractPageState(page.links?.next)
    } while (pageState !== null)
  }

  const hookPath = (system: string, event: string): string =>
    `/webhooks/v1/systems/${encodeURIComponent(system)}/events/${encodeURIComponent(event)}/hooks`

  return {
    hooks: {
      async create({ system, event, ...body }) {
        const response = await request(
          hookPath(system, event),
          jsonInit(body, 'POST'),
          WRITE_SCOPES,
        )
        // 201 with an empty body; the hook id is the Location's last segment.
        const location = response.headers.get('location')
        const hookId = location?.split('/').filter(Boolean).at(-1)
        if (!hookId) {
          throw new Error(
            `APS webhooks create for ${system}/${event} returned no Location header to read the hookId from`,
          )
        }
        return { hookId }
      },
      list: (system, event) => listHooks(hookPath(system, event)),
      listApp: () => listHooks('/webhooks/v1/app/hooks'),
      async delete(system, event, hookId) {
        await request(
          `${hookPath(system, event)}/${encodeURIComponent(hookId)}`,
          { method: 'DELETE' },
          WRITE_SCOPES,
        )
      },
    },
    secretToken: {
      async set(token) {
        await request('/webhooks/v1/tokens', jsonInit({ token }, 'POST'), WRITE_SCOPES)
      },
      async update(token) {
        await request('/webhooks/v1/tokens/@me', jsonInit({ token }, 'PUT'), WRITE_SCOPES)
      },
      async remove() {
        await request('/webhooks/v1/tokens/@me', { method: 'DELETE' }, WRITE_SCOPES)
      },
    },
  }
}
