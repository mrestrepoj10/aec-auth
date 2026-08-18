/**
 * OAuth token-endpoint plumbing shared by the vault backend. Internal — the
 * public surface re-exports from `aec-auth/vault`.
 */
import {
  type AccessToken,
  APS_AUTH,
  type Provider,
  TokenError,
  type TokenErrorCode,
} from '../index'

/** An access token plus the (possibly rotated) refresh token issued with it. */
export interface OAuthTokenResult {
  accessToken: AccessToken
  /**
   * Present when the grant issued or rotated a refresh token. APS rotates on
   * every refresh and invalidates the old token — persist this before using
   * the access token.
   */
  refreshToken?: string
}

/** Parameters for building a provider consent URL. */
export interface AuthorizeUrlParams {
  redirectUri: string
  scopes: readonly string[]
  state?: string
  /** S256 PKCE challenge; `code_challenge_method` is set automatically. */
  codeChallenge?: string
}

/** Parameters for exchanging an authorization code after the consent redirect. */
export interface ExchangeCodeParams {
  code: string
  redirectUri: string
  /** PKCE verifier matching the `codeChallenge` passed to `authorizeUrl`. */
  codeVerifier?: string
}

/**
 * A provider's OAuth endpoints, normalized. `apsOAuth` constructs these;
 * `vaultTokenSource` consumes them.
 */
export interface OAuthProvider {
  readonly provider: Provider
  /** 2-legged app token (`client_credentials`). */
  clientCredentials(scopes?: readonly string[]): Promise<OAuthTokenResult>
  /** 3-legged authorization-code exchange. */
  exchangeCode(params: ExchangeCodeParams): Promise<OAuthTokenResult>
  /** Refresh a user grant. Treat every refresh token as single-use. */
  refresh(refreshToken: string, scopes?: readonly string[]): Promise<OAuthTokenResult>
  /** Consent URL to redirect the user to. */
  authorizeUrl(params: AuthorizeUrlParams): string
}

interface TokenEndpointPayload {
  access_token?: unknown
  expires_in?: unknown
  refresh_token?: unknown
  scope?: unknown
  error?: unknown
  error_description?: unknown
}

function joinScopes(scopes?: readonly string[]): string | undefined {
  return scopes && scopes.length > 0 ? scopes.join(' ') : undefined
}

function formBody(fields: Record<string, string | undefined>): string {
  const params = new URLSearchParams()
  for (const [key, value] of Object.entries(fields)) {
    if (value !== undefined) params.set(key, value)
  }
  return params.toString()
}

function basicAuth(clientId: string, clientSecret: string): string {
  return `Basic ${btoa(`${clientId}:${clientSecret}`)}`
}

async function postToken(
  provider: Provider,
  url: string,
  fields: Record<string, string | undefined>,
  headers?: Record<string, string>,
): Promise<OAuthTokenResult> {
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
      ...headers,
    },
    body: formBody(fields),
  })
  const text = await response.text()
  let payload: TokenEndpointPayload = {}
  try {
    payload = JSON.parse(text) as TokenEndpointPayload
  } catch {
    // Non-JSON error bodies fall through to the status check below.
  }
  if (!response.ok) {
    const error = typeof payload.error === 'string' ? payload.error : undefined
    const detail =
      typeof payload.error_description === 'string'
        ? payload.error_description
        : (error ?? text.slice(0, 200))
    const code: TokenErrorCode = error === 'invalid_grant' ? 'grant_invalid' : 'provider_error'
    throw new TokenError(code, provider, `${provider} token endpoint ${response.status}: ${detail}`)
  }
  if (typeof payload.access_token !== 'string' || typeof payload.expires_in !== 'number') {
    throw new TokenError(
      'provider_error',
      provider,
      `${provider} token endpoint returned a malformed token response`,
    )
  }
  return {
    accessToken: {
      token: payload.access_token,
      expiresAt: Date.now() + payload.expires_in * 1000,
      scopes:
        typeof payload.scope === 'string' && payload.scope !== ''
          ? payload.scope.split(' ')
          : undefined,
    },
    refreshToken: typeof payload.refresh_token === 'string' ? payload.refresh_token : undefined,
  }
}

function buildAuthorizeUrl(base: string, clientId: string, params: AuthorizeUrlParams): string {
  const url = new URL(base)
  url.searchParams.set('response_type', 'code')
  url.searchParams.set('client_id', clientId)
  url.searchParams.set('redirect_uri', params.redirectUri)
  const scope = joinScopes(params.scopes)
  if (scope !== undefined) url.searchParams.set('scope', scope)
  if (params.state !== undefined) url.searchParams.set('state', params.state)
  if (params.codeChallenge !== undefined) {
    url.searchParams.set('code_challenge', params.codeChallenge)
    url.searchParams.set('code_challenge_method', 'S256')
  }
  return url.toString()
}

/**
 * Autodesk Platform Services OAuth v2. Confidential clients (with a
 * `clientSecret`) authenticate with `Authorization: Basic`; public (PKCE)
 * clients send `client_id` in the form body. APS refresh tokens are
 * single-use: every refresh response rotates the refresh token and
 * invalidates the previous one (14-day expiry).
 */
export function apsOAuth(options: {
  clientId: string
  clientSecret?: string
  /**
   * Replace the APS auth origin, e.g. `http://localhost:4014` for the
   * `@emulators/aps` emulator or a portless URL like
   * `https://aps.emulate.localhost`. Endpoint paths stay the real APS ones.
   */
  baseUrl?: string
}): OAuthProvider {
  const { clientId, clientSecret } = options
  const baseUrl = options.baseUrl?.replace(/\/+$/, '')
  const authorizeUrl = baseUrl ? `${baseUrl}/authentication/v2/authorize` : APS_AUTH.authorizeUrl
  const tokenUrl = baseUrl ? `${baseUrl}/authentication/v2/token` : APS_AUTH.tokenUrl
  const confidential = clientSecret !== undefined && clientSecret !== ''
  const headers = confidential ? { Authorization: basicAuth(clientId, clientSecret) } : undefined
  const bodyClient = confidential ? undefined : clientId
  return {
    provider: 'aps',
    async clientCredentials(scopes) {
      if (!confidential) {
        throw new TokenError(
          'not_configured',
          'aps',
          'APS client_credentials (2-legged) requires a clientSecret',
        )
      }
      return postToken(
        'aps',
        tokenUrl,
        { grant_type: 'client_credentials', scope: joinScopes(scopes) },
        headers,
      )
    },
    async exchangeCode({ code, redirectUri, codeVerifier }) {
      return postToken(
        'aps',
        tokenUrl,
        {
          grant_type: 'authorization_code',
          code,
          redirect_uri: redirectUri,
          code_verifier: codeVerifier,
          client_id: bodyClient,
        },
        headers,
      )
    },
    async refresh(refreshToken, scopes) {
      return postToken(
        'aps',
        tokenUrl,
        {
          grant_type: 'refresh_token',
          refresh_token: refreshToken,
          scope: joinScopes(scopes),
          client_id: bodyClient,
        },
        headers,
      )
    },
    authorizeUrl(params) {
      return buildAuthorizeUrl(authorizeUrl, clientId, params)
    },
  }
}
