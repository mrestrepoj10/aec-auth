/**
 * One check per aec-auth backend. Each returns pass, skipped (missing env),
 * or fail — the same ladder as the test suite, run inside a real Next.js
 * server context.
 */
import { isExpired, withTokenCache } from 'aec-auth'
import { createApsClient } from 'aec-auth/aps'
import { apsGenericOAuth } from 'aec-auth/betterauth'
import { connectTokenSource } from 'aec-auth/connect'
import { mockTokenSource } from 'aec-auth/mock'
import { apsOAuth, memoryVaultStore, vaultTokenSource } from 'aec-auth/vault'

export interface Check {
  name: string
  how: string
  status: 'pass' | 'skipped' | 'fail'
  detail: string
}

const APP = { type: 'app' } as const
const CHECK_CACHE_TTL_MS = 60_000

type CheckTask = () => Promise<Check>

export function createChecksRunner(
  tasks: readonly CheckTask[],
  options: { ttlMs?: number; now?: () => number } = {},
): () => Promise<Check[]> {
  const ttlMs = options.ttlMs ?? CHECK_CACHE_TTL_MS
  const now = options.now ?? Date.now
  let cached: { checks: Check[]; expiresAt: number } | undefined
  let pending: Promise<Check[]> | undefined

  return async () => {
    if (cached && now() < cached.expiresAt) return cached.checks
    if (pending) return pending
    pending = Promise.all(tasks.map((task) => task()))
      .then((checks) => {
        cached = { checks, expiresAt: now() + ttlMs }
        return checks
      })
      .finally(() => {
        pending = undefined
      })
    return pending
  }
}

function pass(name: string, how: string, detail: string): Check {
  return { name, how, status: 'pass', detail }
}
function skipped(name: string, how: string, detail: string): Check {
  return { name, how, status: 'skipped', detail }
}
function failed(name: string, how: string, error: unknown): Check {
  return {
    name,
    how,
    status: 'fail',
    detail: error instanceof Error ? error.message : String(error),
  }
}

async function checkMock(): Promise<Check> {
  const name = 'Mock'
  const how = 'aec-auth/mock — zero setup'
  try {
    const token = await mockTokenSource().getToken({ provider: 'aps', subject: APP })
    return pass(name, how, `token ${token.token.slice(0, 24)}…, fresh: ${!isExpired(token)}`)
  } catch (error) {
    return failed(name, how, error)
  }
}

async function checkCache(): Promise<Check> {
  const name = 'Token cache'
  const how = 'withTokenCache — single-flight dedupe'
  try {
    let calls = 0
    const counted = withTokenCache({
      async getToken(request) {
        calls += 1
        return mockTokenSource().getToken(request)
      },
    })
    await Promise.all([
      counted.getToken({ provider: 'aps', subject: APP }),
      counted.getToken({ provider: 'aps', subject: APP }),
      counted.getToken({ provider: 'aps', subject: APP }),
    ])
    if (calls !== 1) return failed(name, how, `expected 1 upstream call, saw ${calls}`)
    return pass(name, how, '3 concurrent requests, 1 upstream call')
  } catch (error) {
    return failed(name, how, error)
  }
}

async function checkVaultEmulator(): Promise<Check> {
  const name = 'Vault + APS emulator'
  const how = 'aec-auth/vault — APS_EMULATOR_URL'
  const baseUrl = process.env.APS_EMULATOR_URL
  if (!baseUrl) return skipped(name, how, 'set APS_EMULATOR_URL (npx emulate --service aps)')
  try {
    const tokens = getEmulatorTokens(baseUrl)
    const token = await tokens.getToken({ provider: 'aps', subject: APP, scopes: ['data:read'] })
    const ttl = Math.round((token.expiresAt - Date.now()) / 1000)
    return pass(name, how, `RS256 JWT minted from ${baseUrl}, expires in ${ttl}s`)
  } catch (error) {
    return failed(name, how, error)
  }
}

let emulatorSource: { baseUrl: string; tokens: ReturnType<typeof vaultTokenSource> } | undefined

function getEmulatorTokens(baseUrl: string): ReturnType<typeof vaultTokenSource> {
  if (emulatorSource?.baseUrl === baseUrl) return emulatorSource.tokens
  const tokens = vaultTokenSource({
    store: memoryVaultStore(),
    providers: {
      aps: apsOAuth({ clientId: 'aps-test-client', clientSecret: 'aps-test-secret', baseUrl }),
    },
  })
  emulatorSource = { baseUrl, tokens }
  return tokens
}

async function checkVaultRealAps(): Promise<Check> {
  const name = 'Vault + real APS (2-legged)'
  const how = 'aec-auth/vault — APS_CLIENT_ID/SECRET'
  const clientId = process.env.APS_CLIENT_ID
  const clientSecret = process.env.APS_CLIENT_SECRET
  if (!clientId || !clientSecret)
    return skipped(name, how, 'set APS_CLIENT_ID and APS_CLIENT_SECRET')
  try {
    const aps = getRealApsClient(clientId, clientSecret)
    const formats = await aps.request<{ formats?: Record<string, unknown> }>(
      '/modelderivative/v2/designdata/formats',
    )
    const count = Object.keys(formats.formats ?? {}).length
    return pass(name, how, `live Model Derivative call OK, ${count} formats`)
  } catch (error) {
    return failed(name, how, error)
  }
}

let realApsClient:
  | {
      clientId: string
      clientSecret: string
      client: ReturnType<typeof createApsClient>
    }
  | undefined

function getRealApsClient(
  clientId: string,
  clientSecret: string,
): ReturnType<typeof createApsClient> {
  if (realApsClient?.clientId === clientId && realApsClient.clientSecret === clientSecret) {
    return realApsClient.client
  }
  const tokens = vaultTokenSource({
    store: memoryVaultStore(),
    providers: { aps: apsOAuth({ clientId, clientSecret }) },
  })
  const client = createApsClient({ tokens, subject: APP })
  realApsClient = { clientId, clientSecret, client }
  return client
}

async function checkConnect(): Promise<Check> {
  const name = 'Vercel Connect'
  const how = 'aec-auth/connect — APS_CONNECTOR'
  const connector = process.env.APS_CONNECTOR
  if (!connector)
    return skipped(name, how, 'set APS_CONNECTOR (vercel connect create) + OIDC token')
  try {
    const tokens = getConnectTokens(connector)
    const token = await tokens.getToken({ provider: 'aps', subject: APP })
    const ttl = Math.round((token.expiresAt - Date.now()) / 1000)
    return pass(name, how, `token via connector '${connector}', expires in ${ttl}s`)
  } catch (error) {
    return failed(name, how, error)
  }
}

let connectSource: { connector: string; tokens: ReturnType<typeof withTokenCache> } | undefined

function getConnectTokens(connector: string): ReturnType<typeof withTokenCache> {
  if (connectSource?.connector === connector) return connectSource.tokens
  const tokens = withTokenCache(connectTokenSource({ connectors: { aps: connector } }))
  connectSource = { connector, tokens }
  return tokens
}

async function checkAuthConfigs(): Promise<Check> {
  const name = 'Better Auth config'
  const how = 'aec-auth/betterauth'
  try {
    const betterauth = apsGenericOAuth({ clientId: 'demo', clientSecret: 'demo' })
    const ok =
      betterauth.providerId === 'aps' &&
      String(betterauth.tokenUrl).includes('/authentication/v2/token')
    if (!ok) return failed(name, how, 'unexpected provider config shape')
    return pass(name, how, 'provider config resolves to the real APS endpoints')
  } catch (error) {
    return failed(name, how, error)
  }
}

export const runChecks = createChecksRunner([
  checkMock,
  checkCache,
  checkVaultEmulator,
  checkVaultRealAps,
  checkConnect,
  checkAuthConfigs,
])
