import { generateKeyPairSync } from 'node:crypto'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { APS_AUTH, TokenError } from '../src/index'
import { apsOAuth, type ServiceAccountKey } from '../src/vault'

interface RecordedCall {
  url: string
  init: RequestInit
}

const okBody = {
  access_token: 'at',
  token_type: 'Bearer',
  expires_in: 3599,
  refresh_token: 'rt-next',
  scope: 'data:read',
}

function stubTokenEndpoint(body: unknown = okBody, status = 200): RecordedCall[] {
  const calls: RecordedCall[] = []
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string | URL, init?: RequestInit) => {
      calls.push({ url: String(url), init: init ?? {} })
      return new Response(JSON.stringify(body), {
        status,
        headers: { 'content-type': 'application/json' },
      })
    }),
  )
  return calls
}

function formOf(call: RecordedCall): URLSearchParams {
  return new URLSearchParams(String(call.init.body))
}

function headerOf(call: RecordedCall, name: string): string | null {
  return new Headers(call.init.headers).get(name)
}

afterEach(() => {
  vi.unstubAllGlobals()
  vi.useRealTimers()
})

describe('apsOAuth', () => {
  const aps = apsOAuth({ clientId: 'cid', clientSecret: 'secret' })

  it('sends Basic auth and form fields for client_credentials', async () => {
    const calls = stubTokenEndpoint()
    await aps.clientCredentials(['data:read', 'data:write'])
    expect(calls).toHaveLength(1)
    const call = calls[0]
    if (!call) throw new Error('no call recorded')
    expect(call.url).toBe(APS_AUTH.tokenUrl)
    expect(call.init.method).toBe('POST')
    expect(headerOf(call, 'authorization')).toBe(`Basic ${btoa('cid:secret')}`)
    expect(headerOf(call, 'content-type')).toBe('application/x-www-form-urlencoded')
    const form = formOf(call)
    expect(form.get('grant_type')).toBe('client_credentials')
    expect(form.get('scope')).toBe('data:read data:write')
    // Confidential clients authenticate via the header, not the body.
    expect(form.get('client_id')).toBeNull()
  })

  it('sends refresh_token grant with Basic auth and maps the rotated token', async () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date(0))
    const calls = stubTokenEndpoint()
    const result = await aps.refresh('rt-old', ['data:read'])
    const call = calls[0]
    if (!call) throw new Error('no call recorded')
    expect(headerOf(call, 'authorization')).toBe(`Basic ${btoa('cid:secret')}`)
    const form = formOf(call)
    expect(form.get('grant_type')).toBe('refresh_token')
    expect(form.get('refresh_token')).toBe('rt-old')
    expect(form.get('scope')).toBe('data:read')
    expect(result.accessToken).toEqual({
      token: 'at',
      expiresAt: 3_599_000,
      scopes: ['data:read'],
    })
    expect(result.refreshToken).toBe('rt-next')
  })

  it('exchanges an authorization code', async () => {
    const calls = stubTokenEndpoint()
    await aps.exchangeCode({ code: 'abc', redirectUri: 'https://app.test/cb' })
    const call = calls[0]
    if (!call) throw new Error('no call recorded')
    const form = formOf(call)
    expect(form.get('grant_type')).toBe('authorization_code')
    expect(form.get('code')).toBe('abc')
    expect(form.get('redirect_uri')).toBe('https://app.test/cb')
  })

  it('public (PKCE) clients send client_id in the body, no Basic auth', async () => {
    const publicClient = apsOAuth({ clientId: 'cid' })
    const calls = stubTokenEndpoint()
    await publicClient.exchangeCode({
      code: 'abc',
      redirectUri: 'https://app.test/cb',
      codeVerifier: 'verifier',
    })
    const call = calls[0]
    if (!call) throw new Error('no call recorded')
    expect(headerOf(call, 'authorization')).toBeNull()
    const form = formOf(call)
    expect(form.get('client_id')).toBe('cid')
    expect(form.get('code_verifier')).toBe('verifier')
  })

  it('client_credentials without a clientSecret is not_configured', async () => {
    stubTokenEndpoint()
    const publicClient = apsOAuth({ clientId: 'cid' })
    const error = await publicClient.clientCredentials(['data:read']).catch((e: unknown) => e)
    expect(error).toBeInstanceOf(TokenError)
    expect((error as TokenError).code).toBe('not_configured')
  })

  it('builds the authorize URL with PKCE parameters', () => {
    const url = new URL(
      aps.authorizeUrl({
        redirectUri: 'https://app.test/cb',
        scopes: ['data:read', 'viewables:read'],
        state: 'xyz',
        codeChallenge: 'challenge',
      }),
    )
    expect(url.origin + url.pathname).toBe(APS_AUTH.authorizeUrl)
    expect(url.searchParams.get('response_type')).toBe('code')
    expect(url.searchParams.get('client_id')).toBe('cid')
    expect(url.searchParams.get('redirect_uri')).toBe('https://app.test/cb')
    expect(url.searchParams.get('scope')).toBe('data:read viewables:read')
    expect(url.searchParams.get('state')).toBe('xyz')
    expect(url.searchParams.get('code_challenge')).toBe('challenge')
    expect(url.searchParams.get('code_challenge_method')).toBe('S256')
  })

  it('maps invalid_grant to TokenError grant_invalid', async () => {
    stubTokenEndpoint({ error: 'invalid_grant', error_description: 'refresh token expired' }, 400)
    const error = await aps.refresh('rt-used').catch((e: unknown) => e)
    expect(error).toBeInstanceOf(TokenError)
    expect((error as TokenError).code).toBe('grant_invalid')
    expect((error as TokenError).provider).toBe('aps')
  })

  it('maps other failures to TokenError provider_error', async () => {
    stubTokenEndpoint({ error: 'server_error' }, 500)
    const error = await aps.clientCredentials(['data:read']).catch((e: unknown) => e)
    expect(error).toBeInstanceOf(TokenError)
    expect((error as TokenError).code).toBe('provider_error')
  })
})

describe('apsOAuth service accounts (jwt-bearer)', () => {
  const { privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  })
  const key: ServiceAccountKey = { keyId: 'kid-1', privateKey }
  const resolver = vi.fn(async (id: string) => (id === 'SA1' ? key : null))
  const aps = apsOAuth({ clientId: 'cid', clientSecret: 'secret', serviceAccountKeys: resolver })

  function decodeSegment(segment: string): Record<string, unknown> {
    const padded = segment.replace(/-/g, '+').replace(/_/g, '/')
    return JSON.parse(
      new TextDecoder().decode(Uint8Array.from(atob(padded), (c) => c.charCodeAt(0))),
    )
  }

  it('posts a signed assertion with the jwt-bearer grant and no scope field', async () => {
    const calls = stubTokenEndpoint()
    const before = Math.floor(Date.now() / 1000)
    const result = await aps.serviceAccount?.('SA1', ['data:read', 'data:write'])
    const after = Math.floor(Date.now() / 1000)
    expect(calls).toHaveLength(1)
    const call = calls[0]
    if (!call) throw new Error('no call recorded')
    expect(call.url).toBe(APS_AUTH.tokenUrl)
    expect(headerOf(call, 'authorization')).toBe(`Basic ${btoa('cid:secret')}`)
    const form = formOf(call)
    expect(form.get('grant_type')).toBe('urn:ietf:params:oauth:grant-type:jwt-bearer')
    // The assertion's scope claim governs — no scope form field.
    expect(form.get('scope')).toBeNull()
    const assertion = form.get('assertion')
    if (!assertion) throw new Error('no assertion in form body')
    const [header, payload] = assertion.split('.') as [string, string]
    expect(decodeSegment(header)).toEqual({ alg: 'RS256', kid: 'kid-1' })
    const claims = decodeSegment(payload)
    expect(claims.iss).toBe('cid')
    expect(claims.sub).toBe('SA1')
    expect(claims.aud).toBe(APS_AUTH.tokenUrl)
    expect(claims.scope).toEqual(['data:read', 'data:write'])
    expect(claims.exp).toBeGreaterThan(before)
    expect(claims.exp).toBeLessThanOrEqual(after + 300)
    expect(result?.accessToken.token).toBe('at')
  })

  it('defaults the assertion scope to data:read when omitted', async () => {
    const calls = stubTokenEndpoint()
    await aps.serviceAccount?.('SA1')
    const call = calls[0]
    if (!call) throw new Error('no call recorded')
    const assertion = formOf(call).get('assertion') ?? ''
    const claims = decodeSegment(assertion.split('.')[1] ?? '')
    expect(claims.scope).toEqual(['data:read'])
  })

  it('requires a clientSecret', async () => {
    stubTokenEndpoint()
    const publicClient = apsOAuth({ clientId: 'cid', serviceAccountKeys: resolver })
    const error = await publicClient.serviceAccount?.('SA1').catch((e: unknown) => e)
    expect(error).toBeInstanceOf(TokenError)
    expect((error as TokenError).code).toBe('not_configured')
  })

  it('requires a serviceAccountKeys resolver', async () => {
    stubTokenEndpoint()
    const withoutKeys = apsOAuth({ clientId: 'cid', clientSecret: 'secret' })
    const error = await withoutKeys.serviceAccount?.('SA1').catch((e: unknown) => e)
    expect(error).toBeInstanceOf(TokenError)
    expect((error as TokenError).code).toBe('not_configured')
  })

  it('is not_configured when the resolver returns null', async () => {
    stubTokenEndpoint()
    const error = await aps.serviceAccount?.('unknown').catch((e: unknown) => e)
    expect(error).toBeInstanceOf(TokenError)
    expect((error as TokenError).code).toBe('not_configured')
    expect((error as TokenError).message).toContain('unknown')
  })

  it('baseUrl override lands in both the POST target and the aud claim', async () => {
    const emulator = apsOAuth({
      clientId: 'cid',
      clientSecret: 'secret',
      serviceAccountKeys: resolver,
      baseUrl: 'http://localhost:4014',
    })
    const calls = stubTokenEndpoint()
    await emulator.serviceAccount?.('SA1')
    const call = calls[0]
    if (!call) throw new Error('no call recorded')
    expect(call.url).toBe('http://localhost:4014/authentication/v2/token')
    const assertion = formOf(call).get('assertion') ?? ''
    const claims = decodeSegment(assertion.split('.')[1] ?? '')
    expect(claims.aud).toBe('http://localhost:4014/authentication/v2/token')
  })
})

describe('apsOAuth baseUrl normalization', () => {
  it('strips trailing slashes before building endpoint URLs', () => {
    const provider = apsOAuth({ clientId: 'id', baseUrl: 'http://localhost:4014/' })
    const url = provider.authorizeUrl({ redirectUri: 'http://localhost:3000/cb', scopes: [] })
    expect(url.startsWith('http://localhost:4014/authentication/v2/authorize?')).toBe(true)
  })
})
