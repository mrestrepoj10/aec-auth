import { describe, expect, it } from 'vitest'
import { isExpired, TokenError, type TokenSource } from '../src/index'
import { apsOAuth, memoryVaultStore, saveUserGrant, vaultTokenSource } from '../src/vault'
import { runTokenSourceConformance } from './conformance'

/**
 * Deterministic integration tests against the `@emulators/aps` emulator
 * (vercel-labs/emulate): a real rotating OAuth server, no credentials, no
 * network beyond localhost. Skipped unless the emulator is running:
 *
 *   npx emulate --service aps          # or from the fork until released
 *   APS_EMULATOR_URL=http://localhost:4014 pnpm vitest run test/aps.emulator.test.ts
 *
 * With portless: APS_EMULATOR_URL=https://aps.emulate.localhost
 */
declare const process: { env: Record<string, string | undefined> }

const emulatorUrl = process.env.APS_EMULATOR_URL?.replace(/\/+$/, '')

// Zero-config defaults seeded by the emulator.
const CLIENT_ID = 'aps-test-client'
const CLIENT_SECRET = 'aps-test-secret'
const REDIRECT_URI = 'http://localhost:3000/callback'

const provider = () =>
  apsOAuth({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET, baseUrl: emulatorUrl })

/** Drives the emulator's consent UI headlessly and returns an auth code. */
async function obtainCode(scopes: readonly string[], state: string): Promise<string> {
  const authorizeUrl = provider().authorizeUrl({ redirectUri: REDIRECT_URI, scopes, state })
  const page = await fetch(authorizeUrl)
  expect(page.status).toBe(200)
  const html = await page.text()
  const userId = html.match(/name="user_id" value="([^"]+)"/)?.[1]
  expect(userId, 'consent page should list the seeded default user').toBeTruthy()

  const form = new URLSearchParams({
    user_id: userId as string,
    redirect_uri: REDIRECT_URI,
    scope: scopes.join(' '),
    state,
    client_id: CLIENT_ID,
    response_mode: 'query',
  })
  const redirect = await fetch(`${emulatorUrl}/authentication/v2/authorize/callback`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form.toString(),
    redirect: 'manual',
  })
  expect(redirect.status).toBe(302)
  const location = new URL(redirect.headers.get('location') ?? '')
  expect(location.searchParams.get('state')).toBe(state)
  const code = location.searchParams.get('code')
  expect(code).toBeTruthy()
  return code as string
}

describe.skipIf(!emulatorUrl)('APS emulator: vault backend end-to-end', () => {
  it('passes TokenSource conformance (2-legged) against the emulator', async () => {
    const source = vaultTokenSource({ store: memoryVaultStore(), providers: { aps: provider() } })
    await runTokenSourceConformance(source, {
      provider: 'aps',
      subject: { type: 'app' },
      scopes: ['data:read'],
    })
  })

  it('mints an RS256 JWT with the documented expiry', async () => {
    const result = await provider().clientCredentials(['data:read'])
    expect(result.accessToken.token.split('.')).toHaveLength(3)
    const remaining = result.accessToken.expiresAt - Date.now()
    expect(remaining).toBeGreaterThan(3_500_000)
    expect(remaining).toBeLessThanOrEqual(3_600_000)
  })

  it('3-legged flow: consent, exchange, rotation, and family invalidation on replay', async () => {
    const oauth = provider()
    const store = memoryVaultStore()
    const tokens: TokenSource = vaultTokenSource({ store, providers: { aps: oauth } })
    const subject = { type: 'user', id: 'u1' } as const
    const scopes = ['data:read'] as const

    const code = await obtainCode(scopes, 'st-emulator')
    const exchanged = await oauth.exchangeCode({ code, redirectUri: REDIRECT_URI })
    expect(exchanged.refreshToken).toBeTruthy()
    const rt0 = exchanged.refreshToken as string

    await saveUserGrant(store, 'aps', 'u1', {
      refreshToken: rt0,
      scopes: [...scopes],
      obtainedAt: Date.now(),
    })

    // Rotation #1: consumes rt0, persists its replacement.
    const first = await tokens.getToken({ provider: 'aps', subject, scopes })
    expect(isExpired(first)).toBe(false)

    // Cache serves the same token without touching the refresh grant.
    const cached = await tokens.getToken({ provider: 'aps', subject, scopes })
    expect(cached.token).toBe(first.token)

    // Rotation #2: only works because rotation #1's token was persisted.
    const second = await tokens.getToken({ provider: 'aps', subject, scopes, forceRefresh: true })
    expect(second.token).not.toBe(first.token)

    // Replaying the original (consumed) refresh token is the production
    // failure mode: the emulator, like real APS, kills the whole grant family.
    const replay = await oauth.refresh(rt0).catch((error: unknown) => error)
    expect(replay).toBeInstanceOf(TokenError)
    expect((replay as TokenError).code).toBe('grant_invalid')

    // The family is dead: even the newest stored refresh token is now invalid.
    const afterReplay = await tokens
      .getToken({ provider: 'aps', subject, scopes, forceRefresh: true })
      .catch((error: unknown) => error)
    expect(afterReplay).toBeInstanceOf(TokenError)
    expect((afterReplay as TokenError).code).toBe('grant_invalid')
  }, 15_000)
})
