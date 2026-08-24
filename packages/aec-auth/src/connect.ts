/**
 * Vercel Connect backend (`aec-auth/connect`): a {@link TokenSource} that
 * resolves tokens through `@vercel/connect` connectors. The SDK is an
 * optional peer, imported lazily (and memoized) on first use, so this module
 * costs nothing when Connect isn't installed.
 */
import {
  type AccessToken,
  type Provider,
  TokenError,
  type TokenSource,
  withTokenCache,
} from './index'

type ConnectModule = typeof import('@vercel/connect')

export interface ConnectTokenSourceOptions {
  /** Connector UID per provider, e.g. `{ aps: 'acme-aps' }`. */
  connectors: Partial<Record<Provider, string>>
  /**
   * Expiry to assume when the Connect response carries none, in milliseconds.
   * Defaults to 55 minutes (APS mints 60-minute tokens).
   */
  defaultTtlMs?: number
}

/** Vercel Connect errors → our stable {@link TokenError} codes. */
function mapConnectError(sdk: ConnectModule, provider: Provider, cause: unknown): TokenError {
  if (cause instanceof TokenError) return cause
  const message = cause instanceof Error ? cause.message : String(cause)
  if (cause instanceof sdk.UserAuthorizationRequiredError) {
    return new TokenError('consent_required', provider, message, { cause })
  }
  if (cause instanceof sdk.ConnectorInstallationRequiredError) {
    return new TokenError('not_configured', provider, message, { cause })
  }
  if (cause instanceof sdk.NoValidTokenError) {
    return new TokenError('grant_invalid', provider, message, { cause })
  }
  return new TokenError('provider_error', provider, message, { cause })
}

/**
 * Builds a {@link TokenSource} backed by Vercel Connect.
 *
 * Always returned wrapped in `withTokenCache`: Connect bills per token
 * request, so every avoidable upstream call is money — cached tokens are
 * served locally until expiry, and concurrent requests share one flight.
 */
export function connectTokenSource(options: ConnectTokenSourceOptions): TokenSource {
  const defaultTtlMs = options.defaultTtlMs ?? 55 * 60_000
  let modulePromise: Promise<ConnectModule> | undefined

  async function loadSdk(provider: Provider): Promise<ConnectModule> {
    modulePromise ??= import('@vercel/connect')
    try {
      return await modulePromise
    } catch (cause) {
      modulePromise = undefined
      throw new TokenError(
        'not_configured',
        provider,
        "connectTokenSource needs the optional peer '@vercel/connect' — install it with " +
          "'npm install @vercel/connect' (or pnpm/yarn/bun add).",
        { cause },
      )
    }
  }

  const source: TokenSource = {
    async getToken(request): Promise<AccessToken> {
      const connector = options.connectors[request.provider]
      if (!connector) {
        throw new TokenError(
          'not_configured',
          request.provider,
          `No Vercel Connect connector configured for provider '${request.provider}'. ` +
            `Add it to connectTokenSource({ connectors: { ${request.provider}: '<connector-uid>' } }).`,
        )
      }
      if (request.subject.type === 'service_account') {
        throw new TokenError(
          'not_configured',
          request.provider,
          'Vercel Connect cannot mint service-account (SSA) tokens: its custom OAuth supports ' +
            'only authorization-code and client-credentials, and SSA needs a signed JWT assertion. ' +
            'Use aec-auth/vault with apsOAuth({ serviceAccountKeys }).',
        )
      }
      const sdk = await loadSdk(request.provider)

      const subject =
        request.subject.type === 'app'
          ? { type: 'app' as const }
          : { type: 'user' as const, id: request.subject.id }

      let response: Awaited<ReturnType<(typeof sdk)['getTokenResponse']>>
      try {
        response = await sdk.getTokenResponse(
          connector,
          { subject, ...(request.scopes ? { scopes: [...request.scopes] } : {}) },
          request.forceRefresh ? { forceRefresh: true } : undefined,
        )
      } catch (cause) {
        throw mapConnectError(sdk, request.provider, cause)
      }

      return {
        token: response.token,
        expiresAt:
          typeof response.expiresAt === 'number' ? response.expiresAt : Date.now() + defaultTtlMs,
        ...(request.scopes ? { scopes: request.scopes } : {}),
      }
    },
  }

  return withTokenCache(source)
}
