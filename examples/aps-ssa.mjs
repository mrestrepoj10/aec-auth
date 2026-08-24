/**
 * Secure Service Account (SSA) smoke test against real APS.
 *
 * Run `pnpm build` first, then:
 *   APS_CLIENT_ID=... APS_CLIENT_SECRET=... \
 *   APS_SSA_ID=... APS_SSA_KEY_ID=... APS_SSA_PRIVATE_KEY="$(cat key.pem)" \
 *   node examples/aps-ssa.mjs
 *
 * The service account id and key come from the SSA management API (or the
 * `aec-auth/ssa` admin client). The token only sees data once an ACC admin
 * has added the app as a custom integration AND invited the service
 * account's email as a member. In your own project these imports are
 * `aec-auth/vault` and `aec-auth/aps`.
 */
import { createApsClient } from '../packages/aec-auth/dist/aps.mjs'
import { apsOAuth, memoryVaultStore, vaultTokenSource } from '../packages/aec-auth/dist/vault.mjs'

const { APS_CLIENT_ID, APS_CLIENT_SECRET, APS_SSA_ID, APS_SSA_KEY_ID, APS_SSA_PRIVATE_KEY } =
  process.env
if (
  !APS_CLIENT_ID ||
  !APS_CLIENT_SECRET ||
  !APS_SSA_ID ||
  !APS_SSA_KEY_ID ||
  !APS_SSA_PRIVATE_KEY
) {
  console.error(
    'Set APS_CLIENT_ID, APS_CLIENT_SECRET, APS_SSA_ID, APS_SSA_KEY_ID, APS_SSA_PRIVATE_KEY',
  )
  process.exit(1)
}

const tokens = vaultTokenSource({
  store: memoryVaultStore(),
  providers: {
    aps: apsOAuth({
      clientId: APS_CLIENT_ID,
      clientSecret: APS_CLIENT_SECRET,
      serviceAccountKeys: async (id) =>
        id === APS_SSA_ID ? { keyId: APS_SSA_KEY_ID, privateKey: APS_SSA_PRIVATE_KEY } : null,
    }),
  },
})

const subject = { type: 'service_account', id: APS_SSA_ID }
const token = await tokens.getToken({ provider: 'aps', subject, scopes: ['data:read'] })
console.log(
  `✓ SSA token minted (jwt-bearer), expires in ${Math.round(
    (token.expiresAt - Date.now()) / 1000,
  )}s`,
)

const aps = createApsClient({ tokens, subject })
const hubs = await aps.hubs.list()
console.log(`✓ Authenticated APS call OK — service account sees ${hubs.data.length} hub(s)`)
if (hubs.data.length === 0) {
  console.log(
    '  (0 hubs usually means the ACC admin provisioning step is missing: add the app as a',
  )
  console.log('  custom integration and invite the service account email as a member.)')
}
console.log('\nSSA path works end to end.')
