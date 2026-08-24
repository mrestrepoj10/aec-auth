/**
 * aec-auth — the token layer for Autodesk Platform Services.
 *
 * This module is the contract. Every backend (`aec-auth/connect`,
 * `aec-auth/vault`, the Better Auth glue) implements `TokenSource`, and the
 * typed client (`aec-auth/aps`) consumes one. Everything here is
 * zero-dependency and runtime-agnostic (WinterCG): plain `fetch`, no Node
 * built-ins.
 */

/**
 * Supported provider. Currently APS only; kept as a named type because future
 * releases re-add union members (e.g. Procore).
 */
export type Provider = 'aps'

/**
 * Who a token acts as: the app itself (2-legged / client-credentials), a
 * specific end user (3-legged / authorization-code), or a Secure Service
 * Account (3-legged / jwt-bearer assertion — no consent, no refresh token).
 */
export type TokenSubject =
  | { type: 'app' }
  | { type: 'user'; id: string }
  | { type: 'service_account'; id: string }

export interface TokenRequest {
  provider: Provider
  subject: TokenSubject
  scopes?: readonly string[]
  /** Skip caches and mint a fresh token. */
  forceRefresh?: boolean
}

export interface AccessToken {
  token: string
  /** Epoch milliseconds. */
  expiresAt: number
  scopes?: readonly string[]
}

export interface TokenSource {
  getToken(request: TokenRequest): Promise<AccessToken>
}

export type TokenErrorCode =
  /** The subject has no stored grant — send the user through consent first. */
  | 'consent_required'
  /** The stored grant no longer works (revoked, expired, or a lost refresh rotation). */
  | 'grant_invalid'
  /** The provider's token endpoint rejected the request or failed. */
  | 'provider_error'
  /** The backend is missing configuration for this provider. */
  | 'not_configured'

export class TokenError extends Error {
  readonly code: TokenErrorCode
  readonly provider: Provider

  constructor(code: TokenErrorCode, provider: Provider, message: string, options?: ErrorOptions) {
    super(message, options)
    this.name = 'TokenError'
    this.code = code
    this.provider = provider
  }
}

/** True when the token is past (or within `skewMs` of) its expiry. */
export function isExpired(token: AccessToken, skewMs = 30_000): boolean {
  return Date.now() + skewMs >= token.expiresAt
}

/** Stable identity for a subject, usable as a storage key segment. */
export function subjectKey(subject: TokenSubject): string {
  if (subject.type === 'app') return 'app'
  return subject.type === 'user' ? `user:${subject.id}` : `sa:${subject.id}`
}

/** Canonical cache key for a token request (scope order is normalized). */
export function requestKey(request: TokenRequest): string {
  const subjectId = request.subject.type === 'app' ? null : request.subject.id
  const scopes = request.scopes === undefined ? null : [...request.scopes].sort()
  return JSON.stringify([request.provider, request.subject.type, subjectId, scopes])
}

/** `Authorization` header for an access token, ready to spread into `fetch` headers. */
export function authHeaders(token: AccessToken): { Authorization: string } {
  return { Authorization: `Bearer ${token.token}` }
}

function startTokenRequest(
  source: TokenSource,
  request: TokenRequest,
  key: string,
  fresh: Map<string, AccessToken>,
  inflight: Map<string, Promise<AccessToken>>,
): Promise<AccessToken> {
  const upstream = source
    .getToken(request)
    .then((token) => {
      fresh.set(key, token)
      return token
    })
    .finally(() => {
      if (inflight.get(key) === upstream) inflight.delete(key)
    })
  inflight.set(key, upstream)
  return upstream
}

/**
 * Wraps a TokenSource with an in-memory, expiry-aware cache and in-process
 * single-flight: concurrent requests for the same key share one upstream call.
 * Backends that bill per token request (Vercel Connect) or rotate refresh
 * tokens on every use (APS) should always sit behind this.
 */
export function withTokenCache(source: TokenSource): TokenSource {
  const fresh = new Map<string, AccessToken>()
  const inflight = new Map<string, Promise<AccessToken>>()

  return {
    async getToken(request) {
      const key = requestKey(request)
      const pending = inflight.get(key)
      if (pending) return pending
      if (!request.forceRefresh) {
        const hit = fresh.get(key)
        if (hit && !isExpired(hit)) return hit
      }
      return startTokenRequest(source, request, key, fresh, inflight)
    },
  }
}

// ---------------------------------------------------------------------------
// Provider endpoints. Single source of truth — backends and auth-library glue
// import these rather than repeating URLs.
// ---------------------------------------------------------------------------

export const APS_AUTH = {
  authorizeUrl: 'https://developer.api.autodesk.com/authentication/v2/authorize',
  tokenUrl: 'https://developer.api.autodesk.com/authentication/v2/token',
  userInfoUrl: 'https://api.userprofile.autodesk.com/userinfo',
} as const

export const APS_BASE_URL = 'https://developer.api.autodesk.com'

// ---------------------------------------------------------------------------
// Scope recipes — named bundles for common tasks, instead of hand-assembled
// scope strings.
// ---------------------------------------------------------------------------

export const apsScopes = {
  /** Load models in the APS Viewer. */
  viewer: ['data:read', 'viewables:read'],
  /** Read hubs, projects, folders, and items. */
  dataRead: ['data:read'],
  /** Read and write project data. */
  dataWrite: ['data:read', 'data:write', 'data:create'],
  /** ACC / BIM 360 account administration. */
  accountAdmin: ['account:read', 'account:write'],
} as const satisfies Record<string, readonly string[]>
