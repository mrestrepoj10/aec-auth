/**
 * One check per aec-auth backend. Each returns pass, skipped (missing env),
 * or fail — the same ladder as the test suite, run inside a real Next.js
 * server context.
 */
import { isExpired, withTokenCache } from 'aec-auth'
import { createApsClient } from 'aec-auth/aps'
import { apsProvider } from 'aec-auth/authjs'
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
    const tokens = vaultTokenSource({
      store: memoryVaultStore(),
      providers: {
        aps: apsOAuth({ clientId: 'aps-test-client', clientSecret: 'aps-test-secret', baseUrl }),
      },
    })
    const token = await tokens.getToken({ provider: 'aps', subject: APP, scopes: ['data:read'] })
    const ttl = Math.round((token.expiresAt - Date.now()) / 1000)
    return pass(name, how, `RS256 JWT minted from ${baseUrl}, expires in ${ttl}s`)
  } catch (error) {
    return failed(name, how, error)
  }
}

async function checkVaultRealAps(): Promise<Check> {
  const name = 'Vault + real APS (2-legged)'
  const how = 'aec-auth/vault — APS_CLIENT_ID/SECRET'
  const clientId = process.env.APS_CLIENT_ID
  const clientSecret = process.env.APS_CLIENT_SECRET
  if (!clientId || !clientSecret)
    return skipped(name, how, 'set APS_CLIENT_ID and APS_CLIENT_SECRET')
  try {
    const tokens = vaultTokenSource({
      store: memoryVaultStore(),
      providers: { aps: apsOAuth({ clientId, clientSecret }) },
    })
    const aps = createApsClient({ tokens, subject: APP })
    const formats = await aps.request<{ formats?: Record<string, unknown> }>(
      '/modelderivative/v2/designdata/formats',
    )
    const count = Object.keys(formats.formats ?? {}).length
    return pass(name, how, `live Model Derivative call OK, ${count} formats`)
  } catch (error) {
    return failed(name, how, error)
  }
}

async function checkConnect(): Promise<Check> {
  const name = 'Vercel Connect'
  const how = 'aec-auth/connect — APS_CONNECTOR'
  const connector = process.env.APS_CONNECTOR
  if (!connector)
    return skipped(name, how, 'set APS_CONNECTOR (vercel connect create) + OIDC token')
  try {
    const tokens = connectTokenSource({ connectors: { aps: connector } })
    const token = await tokens.getToken({ provider: 'aps', subject: APP })
    const ttl = Math.round((token.expiresAt - Date.now()) / 1000)
    return pass(name, how, `token via connector '${connector}', expires in ${ttl}s`)
  } catch (error) {
    return failed(name, how, error)
  }
}

async function checkAuthConfigs(): Promise<Check> {
  const name = 'Auth.js + Better Auth configs'
  const how = 'aec-auth/authjs · aec-auth/betterauth'
  try {
    const authjs = apsProvider({ clientId: 'demo', clientSecret: 'demo' })
    const betterauth = apsGenericOAuth({ clientId: 'demo', clientSecret: 'demo' })
    const ok =
      authjs.id === 'aps' &&
      betterauth.providerId === 'aps' &&
      String(betterauth.tokenUrl).includes('/authentication/v2/token')
    if (!ok) return failed(name, how, 'unexpected provider config shape')
    return pass(name, how, 'provider configs resolve to the real APS endpoints')
  } catch (error) {
    return failed(name, how, error)
  }
}

export async function runChecks(): Promise<Check[]> {
  return Promise.all([
    checkMock(),
    checkCache(),
    checkVaultEmulator(),
    checkVaultRealAps(),
    checkConnect(),
    checkAuthConfigs(),
  ])
}
