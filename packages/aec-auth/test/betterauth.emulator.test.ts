import { betterAuth } from 'better-auth'
import { memoryAdapter } from 'better-auth/adapters/memory'
import { genericOAuth } from 'better-auth/plugins'
import { describe, expect, it } from 'vitest'
import { apsGenericOAuth } from '../src/betterauth'
import { isExpired } from '../src/index'
import { apsOAuth, memoryVaultStore, saveUserGrant, vaultTokenSource } from '../src/vault'

/**
 * The full recommended Better Auth architecture, headless and zero-credential
 * against the `@emulators/aps` emulator: Better Auth owns sign-in and consent
 * (driven entirely in-process via `auth.handler`), the vault takes custody of
 * the refresh token, and all subsequent refresh goes through the vault.
 * Skipped unless the emulator is running (see aps.emulator.test.ts).
 */
declare const process: { env: Record<string, string | undefined> }

const emulatorUrl = process.env.APS_EMULATOR_URL?.replace(/\/+$/, '')
const APP_URL = 'http://localhost:3000'

function collectCookies(response: Response, jar: Map<string, string>): void {
  for (const line of response.headers.getSetCookie()) {
    const [pair] = line.split(';')
    if (!pair) continue
    const eq = pair.indexOf('=')
    if (eq > 0) jar.set(pair.slice(0, eq).trim(), pair.slice(eq + 1))
  }
}

function cookieHeader(jar: Map<string, string>): string {
  return [...jar.entries()].map(([k, v]) => `${k}=${v}`).join('; ')
}

describe.skipIf(!emulatorUrl)('Better Auth sign-in against the APS emulator', () => {
  it('signs in via consent UI, stores a refresh token, and hands custody to the vault', async () => {
    const db = { user: [], session: [], account: [], verification: [] }
    const auth = betterAuth({
      baseURL: APP_URL,
      secret: 'aec-auth-test-secret-aec-auth-test-secret',
      database: memoryAdapter(db),
      plugins: [
        genericOAuth({
          config: [
            apsGenericOAuth({
              clientId: 'aps-test-client',
              clientSecret: 'aps-test-secret',
              baseUrl: emulatorUrl,
            }),
          ],
        }),
      ],
    })
    const jar = new Map<string, string>()

    // 1. Ask Better Auth to start the flow; it returns the authorization URL.
    const signIn = await auth.handler(
      new Request(`${APP_URL}/api/auth/sign-in/oauth2`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ providerId: 'aps', callbackURL: '/done' }),
      }),
    )
    collectCookies(signIn, jar)
    const { url: authorizeUrl } = (await signIn.json()) as { url: string }
    expect(authorizeUrl).toContain(`${emulatorUrl}/authentication/v2/authorize`)
    expect(authorizeUrl).toContain('code_challenge=')

    // 2. The emulator serves a real consent page; drive it headlessly.
    const consent = await fetch(authorizeUrl)
    expect(consent.status).toBe(200)
    const html = await consent.text()
    const fields = new Map<string, string>()
    for (const match of html.matchAll(/name="([^"]+)" value="([^"]*)"/g)) {
      const [, name, value] = match
      if (name !== undefined && value !== undefined && !fields.has(name)) fields.set(name, value)
    }
    expect(fields.get('user_id')).toBeTruthy()
    expect(fields.get('redirect_uri')).toBe(`${APP_URL}/api/auth/oauth2/callback/aps`)

    const redirect = await fetch(`${emulatorUrl}/authentication/v2/authorize/callback`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(Object.fromEntries(fields)).toString(),
      redirect: 'manual',
    })
    expect(redirect.status).toBe(302)
    const callbackUrl = redirect.headers.get('location') as string
    expect(callbackUrl).toContain('/api/auth/oauth2/callback/aps')

    // 3. Feed the provider redirect back into Better Auth: it exchanges the
    // code (PKCE verifier included), fetches userinfo, creates the user.
    const callback = await auth.handler(
      new Request(callbackUrl, { headers: { cookie: cookieHeader(jar) } }),
    )
    collectCookies(callback, jar)
    expect(callback.status).toBe(302)
    expect(callback.headers.get('location')).toContain('/done')

    const [user] = db.user as Array<{ id: string; email?: string; name?: string }>
    expect(user, 'Better Auth should have created a user from emulator userinfo').toBeTruthy()
    expect(user?.email).toBe('testuser@autodesk.local')

    const [account] = db.account as Array<{ providerId: string; refreshToken?: string }>
    expect(account?.providerId).toBe('aps')
    expect(account?.refreshToken, 'accessType offline should yield a refresh token').toBeTruthy()

    // 4. Hand custody to the vault (the single-refresh-owner rule) and prove
    // the vault can rotate the grant Better Auth obtained.
    const store = memoryVaultStore()
    const tokens = vaultTokenSource({
      store,
      providers: {
        aps: apsOAuth({
          clientId: 'aps-test-client',
          clientSecret: 'aps-test-secret',
          baseUrl: emulatorUrl,
        }),
      },
    })
    await saveUserGrant(store, 'aps', (user as { id: string }).id, {
      refreshToken: account?.refreshToken as string,
      obtainedAt: Date.now(),
    })
    // Custody must MOVE, not fork: clear Better Auth's stored copy so nothing
    // can ever replay it after the vault rotates (APS tokens are single-use —
    // a stale replay would invalidate the whole grant family). In an app this
    // is the same account update, done in the sign-in hook.
    ;(db.account[0] as { refreshToken?: string | null }).refreshToken = null
    expect((db.account[0] as { refreshToken?: string | null }).refreshToken).toBeNull()

    const subject = { type: 'user', id: (user as { id: string }).id } as const
    const first = await tokens.getToken({ provider: 'aps', subject, scopes: ['data:read'] })
    expect(isExpired(first)).toBe(false)
    const second = await tokens.getToken({ provider: 'aps', subject, forceRefresh: true })
    expect(second.token).not.toBe(first.token)
  }, 20_000)
})
