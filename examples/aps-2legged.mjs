/**
 * 2-legged smoke test against real APS.
 *
 * Run `pnpm build` first, then:
 *   APS_CLIENT_ID=... APS_CLIENT_SECRET=... node examples/aps-2legged.mjs
 *
 * Credentials come from an app at https://aps.autodesk.com/myapps.
 * In your own project these imports are `aec-auth/vault` and `aec-auth/aps`.
 */
import { createApsClient } from '../packages/aec-auth/dist/aps.mjs'
import { apsOAuth, memoryVaultStore, vaultTokenSource } from '../packages/aec-auth/dist/vault.mjs'

// APS_BASE_URL points the flow at the @emulators/aps emulator instead of real
// APS, e.g. http://localhost:4000 or https://aps.emulate.localhost (portless).
const { APS_BASE_URL } = process.env
const emulator = Boolean(APS_BASE_URL)
const APS_CLIENT_ID = process.env.APS_CLIENT_ID ?? (emulator ? 'aps-test-client' : undefined)
const APS_CLIENT_SECRET =
  process.env.APS_CLIENT_SECRET ?? (emulator ? 'aps-test-secret' : undefined)
if (!APS_CLIENT_ID || !APS_CLIENT_SECRET) {
  console.error('Set APS_CLIENT_ID and APS_CLIENT_SECRET (https://aps.autodesk.com/myapps)')
  console.error('Or set APS_BASE_URL to an @emulators/aps URL for a zero-credential run.')
  process.exit(1)
}

const tokens = vaultTokenSource({
  store: memoryVaultStore(),
  providers: {
    aps: apsOAuth({
      clientId: APS_CLIENT_ID,
      clientSecret: APS_CLIENT_SECRET,
      baseUrl: APS_BASE_URL,
    }),
  },
})

const token = await tokens.getToken({
  provider: 'aps',
  subject: { type: 'app' },
  scopes: ['data:read'],
})
console.log(
  `✓ 2-legged token minted (client_credentials), expires in ${Math.round(
    (token.expiresAt - Date.now()) / 1000,
  )}s`,
)

if (emulator) {
  console.log(
    '✓ Emulator run — data APIs (Model Derivative) are not emulated yet, skipping the API call',
  )
} else {
  const aps = createApsClient({ tokens, subject: { type: 'app' } })
  const formats = await aps.request('/modelderivative/v2/designdata/formats')
  const count = Object.keys(formats.formats ?? {}).length
  console.log(`✓ Authenticated APS call OK — Model Derivative lists ${count} output formats`)
}
console.log('\n2-legged path works end to end.')
