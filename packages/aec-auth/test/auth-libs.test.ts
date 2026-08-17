import { describe, expect, it } from 'vitest'
import { apsProvider, procoreProvider } from '../src/authjs'
import { apsGenericOAuth, procoreGenericOAuth } from '../src/betterauth'
import { APS_AUTH, PROCORE_AUTH } from '../src/index'

const credentials = { clientId: 'client-id', clientSecret: 'client-secret' }

describe('authjs apsProvider', () => {
  it('carries the APS endpoints, checks, and default viewer scopes', () => {
    const provider = apsProvider(credentials)

    expect(provider.id).toBe('aps')
    expect(provider.type).toBe('oauth')
    expect(provider.authorization).toEqual({
      url: APS_AUTH.authorizeUrl,
      params: { scope: 'data:read viewables:read' },
    })
    expect(provider.token).toBe(APS_AUTH.tokenUrl)
    expect(provider.userinfo).toBe(APS_AUTH.userInfoUrl)
    expect(provider.checks).toEqual(['state', 'pkce'])
    expect(provider.clientId).toBe('client-id')
    expect(provider.clientSecret).toBe('client-secret')
  })

  it('joins custom scopes into the authorization scope param', () => {
    const provider = apsProvider({ ...credentials, scopes: ['data:read', 'data:write'] })

    expect(provider.authorization).toMatchObject({ params: { scope: 'data:read data:write' } })
  })

  it('maps the APS userinfo claims to an Auth.js user', async () => {
    const provider = apsProvider(credentials)

    const user = await provider.profile?.(
      {
        sub: 'aps-123',
        name: 'Ada Lovelace',
        email: 'ada@example.com',
        picture: 'https://x/y.png',
      },
      {},
    )

    expect(user).toEqual({
      id: 'aps-123',
      name: 'Ada Lovelace',
      email: 'ada@example.com',
      image: 'https://x/y.png',
    })
  })
})

describe('authjs procoreProvider', () => {
  it('carries the production endpoints by default', () => {
    const provider = procoreProvider(credentials)

    expect(provider.id).toBe('procore')
    expect(provider.type).toBe('oauth')
    expect(provider.authorization).toBe(PROCORE_AUTH.authorizeUrl)
    expect(provider.token).toBe(PROCORE_AUTH.tokenUrl)
    expect(provider.userinfo).toBe('https://api.procore.com/rest/v1.0/me')
  })

  it('switches every endpoint when sandbox is set', () => {
    const provider = procoreProvider({ ...credentials, sandbox: true })

    expect(provider.authorization).toBe(PROCORE_AUTH.sandbox.authorizeUrl)
    expect(provider.token).toBe(PROCORE_AUTH.sandbox.tokenUrl)
    expect(provider.userinfo).toBe('https://sandbox.procore.com/rest/v1.0/me')
  })

  it('maps /me to an Auth.js user with login as email', async () => {
    const provider = procoreProvider(credentials)

    const user = await provider.profile?.({ id: 42, login: 'dev@example.com', name: 'Dev' }, {})

    expect(user).toEqual({ id: '42', name: 'Dev', email: 'dev@example.com' })
  })
})

describe('betterauth apsGenericOAuth', () => {
  it('carries the APS endpoints, pkce, offline access, and default scopes', () => {
    const config = apsGenericOAuth(credentials)

    expect(config).toEqual({
      providerId: 'aps',
      clientId: 'client-id',
      clientSecret: 'client-secret',
      authorizationUrl: APS_AUTH.authorizeUrl,
      tokenUrl: APS_AUTH.tokenUrl,
      userInfoUrl: APS_AUTH.userInfoUrl,
      scopes: ['data:read', 'viewables:read'],
      pkce: true,
      accessType: 'offline',
    })
  })

  it('honors custom scopes', () => {
    const config = apsGenericOAuth({ ...credentials, scopes: ['account:read'] })

    expect(config.scopes).toEqual(['account:read'])
  })
})

describe('betterauth procoreGenericOAuth', () => {
  it('carries the production endpoints by default', () => {
    const config = procoreGenericOAuth(credentials)

    expect(config.providerId).toBe('procore')
    expect(config.authorizationUrl).toBe(PROCORE_AUTH.authorizeUrl)
    expect(config.tokenUrl).toBe(PROCORE_AUTH.tokenUrl)
    expect(config.userInfoUrl).toBe('https://api.procore.com/rest/v1.0/me')
    expect(config.pkce).toBe(true)
  })

  it('switches every endpoint when sandbox is set', () => {
    const config = procoreGenericOAuth({ ...credentials, sandbox: true })

    expect(config.authorizationUrl).toBe(PROCORE_AUTH.sandbox.authorizeUrl)
    expect(config.tokenUrl).toBe(PROCORE_AUTH.sandbox.tokenUrl)
    expect(config.userInfoUrl).toBe('https://sandbox.procore.com/rest/v1.0/me')
  })
})

describe('baseUrl override (APS emulator support)', () => {
  const baseUrl = 'http://localhost:4014'

  it('apsProvider points every endpoint at the override origin', () => {
    const provider = apsProvider({ ...credentials, baseUrl })

    expect((provider.authorization as { url: string }).url).toBe(
      `${baseUrl}/authentication/v2/authorize`,
    )
    expect(provider.token).toBe(`${baseUrl}/authentication/v2/token`)
    expect(provider.userinfo).toBe(`${baseUrl}/userinfo`)
  })

  it('apsGenericOAuth points every endpoint at the override origin', () => {
    const config = apsGenericOAuth({ ...credentials, baseUrl })

    expect(config.authorizationUrl).toBe(`${baseUrl}/authentication/v2/authorize`)
    expect(config.tokenUrl).toBe(`${baseUrl}/authentication/v2/token`)
    expect(config.userInfoUrl).toBe(`${baseUrl}/userinfo`)
  })

  it('without the override, real APS endpoints are untouched', () => {
    expect(apsGenericOAuth(credentials).tokenUrl).toBe(APS_AUTH.tokenUrl)
    expect(apsProvider(credentials).token).toBe(APS_AUTH.tokenUrl)
  })
})
