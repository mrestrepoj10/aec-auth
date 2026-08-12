/**
 * 3-legged end-to-end test against real APS + your ACC account.
 *
 * What it proves, in order:
 *   1. authorization-code exchange works,
 *   2. the vault refreshes with the stored grant (refresh #1),
 *   3. your ACC hub + projects come back from the Data Management API,
 *   4. a forced second refresh works — i.e. the ROTATED refresh token was
 *      persisted correctly (the failure mode this package exists to prevent).
 *
 * Setup: in your APS app (https://aps.autodesk.com/myapps), register the
 * callback URL http://localhost:8787/callback . Then run `pnpm build` and:
 *   APS_CLIENT_ID=... APS_CLIENT_SECRET=... node examples/aps-3legged.mjs
 * Sign in with the Autodesk account that has access to your ACC hub.
 *
 * In your own project these imports are `aec-auth/vault` and `aec-auth/aps`.
 */
import { randomBytes } from 'node:crypto'
import { createServer } from 'node:http'
import { createApsClient } from '../packages/aec-auth/dist/aps.mjs'
import {
  apsOAuth,
  memoryVaultStore,
  saveUserGrant,
  vaultTokenSource,
} from '../packages/aec-auth/dist/vault.mjs'

const { APS_CLIENT_ID, APS_CLIENT_SECRET } = process.env
if (!APS_CLIENT_ID || !APS_CLIENT_SECRET) {
  console.error('Set APS_CLIENT_ID and APS_CLIENT_SECRET (https://aps.autodesk.com/myapps)')
  process.exit(1)
}

const PORT = Number(process.env.PORT ?? 8787)
const redirectUri = `http://localhost:${PORT}/callback`
const scopes = ['data:read', 'viewables:read']
const state = randomBytes(16).toString('hex')

const provider = apsOAuth({ clientId: APS_CLIENT_ID, clientSecret: APS_CLIENT_SECRET })
const store = memoryVaultStore()
const tokens = vaultTokenSource({ store, providers: { aps: provider } })
const subject = { type: 'user', id: 'me' }

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', `http://localhost:${PORT}`)
  if (url.pathname !== '/callback') {
    res.writeHead(404).end()
    return
  }
  try {
    if (url.searchParams.get('state') !== state) throw new Error('state mismatch')
    const code = url.searchParams.get('code')
    if (!code) throw new Error(`no code in callback: ${url.search}`)

    const result = await provider.exchangeCode({ code, redirectUri })
    if (!result.refreshToken) throw new Error('APS returned no refresh token')
    await saveUserGrant(store, 'aps', 'me', {
      refreshToken: result.refreshToken,
      scopes,
      obtainedAt: Date.now(),
    })
    console.log('✓ Code exchanged, grant stored')

    // The vault has no cached access token yet, so this consumes the stored
    // refresh token (rotation #1) and must persist its replacement.
    const token = await tokens.getToken({ provider: 'aps', subject, scopes: ['data:read'] })
    console.log(
      `✓ Refresh #1 via vault, token expires in ${Math.round(
        (token.expiresAt - Date.now()) / 1000,
      )}s`,
    )

    const aps = createApsClient({ tokens, subject })
    const hubs = await aps.hubs.list()
    console.log(`✓ ${hubs.data.length} hub(s) visible to this account:`)
    for (const hub of hubs.data) console.log(`    ${hub.id}  ${hub.attributes.name ?? ''}`)

    const first = hubs.data[0]
    if (first) {
      const projects = await aps.projects.list(first.id)
      console.log(`✓ ${projects.data.length} project(s) in ${first.attributes.name ?? first.id}:`)
      for (const p of projects.data.slice(0, 10)) console.log(`    ${p.attributes.name ?? p.id}`)
    }

    // Forced refresh #2: only succeeds if rotation #1's new refresh token was
    // persisted — this is the single-use-token failure mode, exercised live.
    await tokens.getToken({ provider: 'aps', subject, scopes: ['data:read'], forceRefresh: true })
    console.log('✓ Refresh #2 (forced) with the rotated token — rotation persistence verified')

    res.writeHead(200, { 'content-type': 'text/html' })
    res.end('<h3>aec-auth: all checks passed — see the terminal. You can close this tab.</h3>')
    console.log('\n3-legged path works end to end. Ctrl+C to exit.')
  } catch (error) {
    console.error('✗', error)
    res.writeHead(500, { 'content-type': 'text/plain' })
    res.end(String(error))
  }
})

server.listen(PORT, () => {
  const url = provider.authorizeUrl({ redirectUri, scopes, state })
  console.log('Open this URL and sign in with your ACC-enabled Autodesk account:\n')
  console.log(`  ${url}\n`)
})
