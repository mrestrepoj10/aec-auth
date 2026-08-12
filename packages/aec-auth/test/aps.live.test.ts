import { describe, expect, it } from 'vitest'
import { createApsClient } from '../src/aps'
import { connectTokenSource } from '../src/connect'
import { apsOAuth, memoryVaultStore, vaultTokenSource } from '../src/vault'
import { runTokenSourceConformance } from './conformance'

/**
 * Live integration against the real APS OAuth server + Model Derivative API.
 * Skipped entirely unless credentials are present, so the default suite stays
 * deterministic. Run with:
 *
 *   APS_CLIENT_ID=... APS_CLIENT_SECRET=... pnpm vitest run test/aps.live.test.ts
 *
 * The Connect block additionally needs a Custom OAuth connector for APS and a
 * Vercel OIDC token in the environment (`vc env pull`):
 *
 *   APS_CONNECTOR=<connector-uid> ... pnpm vitest run test/aps.live.test.ts
 */
// The library itself is WinterCG-clean, so `node` types stay out of tsconfig;
// this test runner is Node, declared locally.
declare const process: { env: Record<string, string | undefined> }

const clientId = process.env.APS_CLIENT_ID
const clientSecret = process.env.APS_CLIENT_SECRET
const connector = process.env.APS_CONNECTOR

const LIVE_TIMEOUT = 30_000

describe.skipIf(!clientId || !clientSecret)('live: vault backend, 2-legged APS', () => {
  const makeSource = () =>
    vaultTokenSource({
      store: memoryVaultStore(),
      providers: {
        aps: apsOAuth({ clientId: clientId as string, clientSecret: clientSecret as string }),
      },
    })

  it(
    'passes TokenSource conformance against the real token endpoint',
    async () => {
      await runTokenSourceConformance(makeSource(), {
        provider: 'aps',
        subject: { type: 'app' },
        scopes: ['data:read'],
      })
    },
    LIVE_TIMEOUT,
  )

  it(
    'serves the same cached token from the store until expiry',
    async () => {
      const source = makeSource()
      const request = {
        provider: 'aps',
        subject: { type: 'app' },
        scopes: ['data:read'],
      } as const
      const first = await source.getToken(request)
      const second = await source.getToken(request)
      expect(second.token).toBe(first.token)
      expect(first.expiresAt - Date.now()).toBeGreaterThan(60_000)
    },
    LIVE_TIMEOUT,
  )

  it(
    'makes an authenticated Model Derivative call through the typed client',
    async () => {
      const aps = createApsClient({ tokens: makeSource(), subject: { type: 'app' } })
      const formats = await aps.request<{ formats?: Record<string, unknown> }>(
        '/modelderivative/v2/designdata/formats',
      )
      expect(Object.keys(formats.formats ?? {}).length).toBeGreaterThan(0)
    },
    LIVE_TIMEOUT,
  )
})

describe.skipIf(!connector)('live: Vercel Connect backend', () => {
  it(
    'passes TokenSource conformance through the connector',
    async () => {
      const source = connectTokenSource({
        connectors: { aps: connector as string },
      })
      await runTokenSourceConformance(source, {
        provider: 'aps',
        subject: { type: 'app' },
      })
    },
    LIVE_TIMEOUT,
  )

  it(
    'the typed client works identically on the Connect backend',
    async () => {
      const tokens = connectTokenSource({ connectors: { aps: connector as string } })
      const aps = createApsClient({ tokens, subject: { type: 'app' } })
      const formats = await aps.request<{ formats?: Record<string, unknown> }>(
        '/modelderivative/v2/designdata/formats',
      )
      expect(Object.keys(formats.formats ?? {}).length).toBeGreaterThan(0)
    },
    LIVE_TIMEOUT,
  )
})
