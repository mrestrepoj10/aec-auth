import { afterEach, describe, expect, it, vi } from 'vitest'
import { APS_AUTH, PROCORE_AUTH, TokenError } from '../src/index'
import { apsOAuth, procoreOAuth } from '../src/vault'

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

describe('procoreOAuth', () => {
  it('hits production endpoints by default with body credentials', async () => {
    const calls = stubTokenEndpoint()
    const procore = procoreOAuth({ clientId: 'cid', clientSecret: 'secret' })
    await procore.clientCredentials()
    const call = calls[0]
    if (!call) throw new Error('no call recorded')
    expect(call.url).toBe(PROCORE_AUTH.tokenUrl)
    const form = formOf(call)
    expect(form.get('grant_type')).toBe('client_credentials')
    expect(form.get('client_id')).toBe('cid')
    expect(form.get('client_secret')).toBe('secret')
  })

  it('hits sandbox endpoints when sandbox: true', async () => {
    const calls = stubTokenEndpoint()
    const procore = procoreOAuth({ clientId: 'cid', clientSecret: 'secret', sandbox: true })
    await procore.refresh('rt-old')
    const call = calls[0]
    if (!call) throw new Error('no call recorded')
    expect(call.url).toBe(PROCORE_AUTH.sandbox.tokenUrl)
    const form = formOf(call)
    expect(form.get('grant_type')).toBe('refresh_token')
    expect(form.get('refresh_token')).toBe('rt-old')
    const authorize = procore.authorizeUrl({ redirectUri: 'https://app.test/cb', scopes: [] })
    expect(authorize.startsWith(PROCORE_AUTH.sandbox.authorizeUrl)).toBe(true)
  })

  it('maps invalid_grant on refresh to grant_invalid', async () => {
    stubTokenEndpoint({ error: 'invalid_grant' }, 401)
    const procore = procoreOAuth({ clientId: 'cid', clientSecret: 'secret' })
    const error = await procore.refresh('rt-used').catch((e: unknown) => e)
    expect(error).toBeInstanceOf(TokenError)
    expect((error as TokenError).code).toBe('grant_invalid')
    expect((error as TokenError).provider).toBe('procore')
  })
})

describe('apsOAuth baseUrl normalization', () => {
  it('strips trailing slashes before building endpoint URLs', () => {
    const provider = apsOAuth({ clientId: 'id', baseUrl: 'http://localhost:4014/' })
    const url = provider.authorizeUrl({ redirectUri: 'http://localhost:3000/cb', scopes: [] })
    expect(url.startsWith('http://localhost:4014/authentication/v2/authorize?')).toBe(true)
  })
})
