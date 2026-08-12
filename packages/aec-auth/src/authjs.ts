/**
 * Auth.js (NextAuth) provider configs (`aec-auth/authjs`) for APS and
 * Procore. Imports from `@auth/core` are type-only, so the optional peer is
 * never a runtime dependency.
 */
import type { OAuth2Config } from '@auth/core/providers'
import {
  APS_AUTH,
  apsScopes,
  PROCORE_AUTH,
  PROCORE_BASE_URL,
  PROCORE_SANDBOX_BASE_URL,
} from './index'

/** Claims returned by the APS userinfo endpoint (OIDC-shaped). */
export interface ApsProfile {
  sub: string
  name?: string
  email?: string
  email_verified?: boolean
  picture?: string
  [claim: string]: unknown
}

/** The authenticated user as returned by Procore's `/rest/v1.0/me`. */
export interface ProcoreProfile {
  id: number
  login?: string
  name?: string
  [key: string]: unknown
}

export interface ApsProviderOptions {
  clientId: string
  clientSecret: string
  /** OAuth scopes to request. Defaults to `apsScopes.viewer`. */
  scopes?: readonly string[]
}

/**
 * Auth.js OAuth provider for Autodesk Platform Services (3-legged).
 *
 * APS uses the standard `scope` parameter and issues refresh tokens
 * automatically on the authorization-code flow — no offline-access scope
 * needed. PKCE and state are both enforced.
 */
export function apsProvider(options: ApsProviderOptions): OAuth2Config<ApsProfile> {
  const scope = (options.scopes ?? apsScopes.viewer).join(' ')
  return {
    id: 'aps',
    name: 'Autodesk',
    type: 'oauth',
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    authorization: { url: APS_AUTH.authorizeUrl, params: { scope } },
    token: APS_AUTH.tokenUrl,
    userinfo: APS_AUTH.userInfoUrl,
    checks: ['state', 'pkce'],
    profile(profile) {
      return {
        id: profile.sub,
        name: profile.name ?? null,
        email: profile.email ?? null,
        image: profile.picture ?? null,
      }
    },
  }
}

export interface ProcoreProviderOptions {
  clientId: string
  clientSecret: string
  /** Point login and API at Procore's sandbox environment. */
  sandbox?: boolean
}

/**
 * Auth.js OAuth provider for Procore. Sandbox-aware: `sandbox: true` switches
 * both the login endpoints and the `/rest/v1.0/me` userinfo URL. Procore has
 * no userinfo scopes — an empty `scope` grants full access of the app.
 */
export function procoreProvider(options: ProcoreProviderOptions): OAuth2Config<ProcoreProfile> {
  const auth = options.sandbox ? PROCORE_AUTH.sandbox : PROCORE_AUTH
  const apiBase = options.sandbox ? PROCORE_SANDBOX_BASE_URL : PROCORE_BASE_URL
  return {
    id: 'procore',
    name: 'Procore',
    type: 'oauth',
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    authorization: auth.authorizeUrl,
    token: auth.tokenUrl,
    userinfo: `${apiBase}/rest/v1.0/me`,
    checks: ['state'],
    profile(profile) {
      return {
        id: String(profile.id),
        name: profile.name ?? null,
        email: profile.login ?? null,
      }
    },
  }
}
