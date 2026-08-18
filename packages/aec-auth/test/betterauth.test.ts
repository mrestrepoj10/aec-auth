import { describe, expect, it } from 'vitest'
import { apsGenericOAuth } from '../src/betterauth'
import { APS_AUTH } from '../src/index'

const credentials = { clientId: 'client-id', clientSecret: 'client-secret' }

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

describe('baseUrl override (APS emulator support)', () => {
  const baseUrl = 'http://localhost:4014'

  it('points every endpoint at the override origin', () => {
    const config = apsGenericOAuth({ ...credentials, baseUrl })

    expect(config.authorizationUrl).toBe(`${baseUrl}/authentication/v2/authorize`)
    expect(config.tokenUrl).toBe(`${baseUrl}/authentication/v2/token`)
    expect(config.userInfoUrl).toBe(`${baseUrl}/userinfo`)
  })

  it('without the override, real APS endpoints are untouched', () => {
    expect(apsGenericOAuth(credentials).tokenUrl).toBe(APS_AUTH.tokenUrl)
  })

  it('strips trailing slashes before appending paths', () => {
    const config = apsGenericOAuth({ ...credentials, baseUrl: 'http://localhost:4014/' })

    expect(config.tokenUrl).toBe('http://localhost:4014/authentication/v2/token')
    expect(config.userInfoUrl).toBe('http://localhost:4014/userinfo')
  })
})
