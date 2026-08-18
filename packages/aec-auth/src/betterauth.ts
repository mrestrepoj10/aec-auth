/**
 * Better Auth `genericOAuth` entry (`aec-auth/betterauth`) for Autodesk
 * Platform Services. Imports from `better-auth` are type-only, so the
 * optional peer is never a runtime dependency. Drop the returned config into
 * `genericOAuth({ config: [...] })`.
 */
import type { GenericOAuthConfig } from 'better-auth/plugins/generic-oauth'
import { APS_AUTH, apsScopes } from './index'

export interface ApsGenericOAuthOptions {
  clientId: string
  clientSecret: string
  /** OAuth scopes to request. Defaults to `apsScopes.viewer`. */
  scopes?: readonly string[]
  /**
   * Replace the APS auth origin, e.g. `http://localhost:4014` for the
   * `@emulators/aps` emulator — makes the whole Better Auth sign-in flow a
   * zero-credential test. Endpoint paths stay the real APS ones (userinfo
   * maps onto the same origin, as the emulator serves it).
   */
  baseUrl?: string
}

/**
 * Better Auth generic OAuth config for Autodesk Platform Services.
 *
 * APS issues refresh tokens automatically on 3-legged flows; `accessType:
 * 'offline'` is set for providers that gate refresh tokens on it and is
 * ignored by APS.
 */
export function apsGenericOAuth(options: ApsGenericOAuthOptions): GenericOAuthConfig {
  const baseUrl = options.baseUrl?.replace(/\/+$/, '')
  return {
    providerId: 'aps',
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    authorizationUrl: baseUrl ? `${baseUrl}/authentication/v2/authorize` : APS_AUTH.authorizeUrl,
    tokenUrl: baseUrl ? `${baseUrl}/authentication/v2/token` : APS_AUTH.tokenUrl,
    userInfoUrl: baseUrl ? `${baseUrl}/userinfo` : APS_AUTH.userInfoUrl,
    scopes: [...(options.scopes ?? apsScopes.viewer)],
    pkce: true,
    accessType: 'offline',
  }
}
