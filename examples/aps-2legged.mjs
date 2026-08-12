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

const { APS_CLIENT_ID, APS_CLIENT_SECRET } = process.env
if (!APS_CLIENT_ID || !APS_CLIENT_SECRET) {
  console.error('Set APS_CLIENT_ID and APS_CLIENT_SECRET (https://aps.autodesk.com/myapps)')
  process.exit(1)
}

const tokens = vaultTokenSource({
  store: memoryVaultStore(),
  providers: {
    aps: apsOAuth({ clientId: APS_CLIENT_ID, clientSecret: APS_CLIENT_SECRET }),
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

const aps = createApsClient({ tokens, subject: { type: 'app' } })
const formats = await aps.request('/modelderivative/v2/designdata/formats')
const count = Object.keys(formats.formats ?? {}).length
console.log(`✓ Authenticated APS call OK — Model Derivative lists ${count} output formats`)
console.log('\n2-legged path works end to end.')
