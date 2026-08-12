import { describe, it } from 'vitest'
import { withTokenCache } from '../src/index'
import { mockTokenSource } from '../src/mock'
import {
  memoryVaultStore,
  type OAuthProvider,
  type OAuthTokenResult,
  saveUserGrant,
  vaultTokenSource,
} from '../src/vault'
import { runTokenSourceConformance } from './conformance'

/** Deterministic in-memory provider: fresh tokens, rotating single-use refresh. */
function fakeProvider(): OAuthProvider {
  let minted = 0
  let rotation = 0
  const issued = new Set<string>(['rt-0'])
  const result = (refreshToken?: string): OAuthTokenResult => ({
    accessToken: {
      token: `at-${minted++}`,
      expiresAt: Date.now() + 3_600_000,
    },
    ...(refreshToken !== undefined ? { refreshToken } : {}),
  })
  return {
    provider: 'aps',
    clientCredentials: async () => result(),
    exchangeCode: async () => result(`rt-${++rotation}`),
    refresh: async (refreshToken) => {
      if (!issued.delete(refreshToken)) throw new Error(`refresh token replayed: ${refreshToken}`)
      const next = `rt-${++rotation}`
      issued.add(next)
      return result(next)
    },
    authorizeUrl: () => 'https://example.test/authorize',
  }
}

describe('TokenSource conformance', () => {
  it('mockTokenSource', async () => {
    await runTokenSourceConformance(mockTokenSource(), {
      provider: 'aps',
      subject: { type: 'app' },
    })
  })

  it('withTokenCache(mockTokenSource)', async () => {
    await runTokenSourceConformance(withTokenCache(mockTokenSource()), {
      provider: 'aps',
      subject: { type: 'app' },
      scopes: ['data:read'],
    })
  })

  it('vaultTokenSource — app subject', async () => {
    const source = vaultTokenSource({
      store: memoryVaultStore(),
      providers: { aps: fakeProvider() },
    })
    await runTokenSourceConformance(source, {
      provider: 'aps',
      subject: { type: 'app' },
      scopes: ['data:read'],
    })
  })

  it('vaultTokenSource — user subject with rotating grant', async () => {
    const store = memoryVaultStore()
    await saveUserGrant(store, 'aps', 'u1', {
      refreshToken: 'rt-0',
      scopes: ['data:read'],
      obtainedAt: Date.now(),
    })
    const source = vaultTokenSource({ store, providers: { aps: fakeProvider() } })
    await runTokenSourceConformance(source, {
      provider: 'aps',
      subject: { type: 'user', id: 'u1' },
      scopes: ['data:read'],
    })
  })
})
