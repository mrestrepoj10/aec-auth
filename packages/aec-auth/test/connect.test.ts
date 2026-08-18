import { UserAuthorizationRequiredError } from '@vercel/connect'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { connectTokenSource } from '../src/connect'

const mocks = vi.hoisted(() => ({
  getTokenResponse: vi.fn(),
}))

vi.mock('@vercel/connect', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@vercel/connect')>()
  return { ...actual, getTokenResponse: mocks.getTokenResponse }
})

beforeEach(() => {
  mocks.getTokenResponse.mockReset()
  mocks.getTokenResponse.mockResolvedValue({
    token: 'stk-token',
    expiresAt: Date.now() + 3_600_000,
    connector: { id: 'con_1', uid: 'acme-aps', type: 'oauth' },
  })
})

describe('connectTokenSource', () => {
  it('maps an app subject to the SDK subject shape', async () => {
    const source = connectTokenSource({ connectors: { aps: 'acme-aps' } })

    const token = await source.getToken({ provider: 'aps', subject: { type: 'app' } })

    expect(token.token).toBe('stk-token')
    expect(mocks.getTokenResponse).toHaveBeenCalledWith(
      'acme-aps',
      { subject: { type: 'app' } },
      undefined,
    )
  })

  it('maps a user subject and passes scopes through', async () => {
    const source = connectTokenSource({ connectors: { aps: 'acme-aps' } })

    await source.getToken({
      provider: 'aps',
      subject: { type: 'user', id: 'u1' },
      scopes: ['data:read'],
    })

    expect(mocks.getTokenResponse).toHaveBeenCalledWith(
      'acme-aps',
      { subject: { type: 'user', id: 'u1' }, scopes: ['data:read'] },
      undefined,
    )
  })

  it('caches tokens: two sequential getToken calls hit the SDK once', async () => {
    const source = connectTokenSource({ connectors: { aps: 'acme-aps' } })
    const request = { provider: 'aps', subject: { type: 'app' } } as const

    const first = await source.getToken(request)
    const second = await source.getToken(request)

    expect(second).toBe(first)
    expect(mocks.getTokenResponse).toHaveBeenCalledTimes(1)
  })

  it('bypasses the cache and forwards forceRefresh to the SDK', async () => {
    const source = connectTokenSource({ connectors: { aps: 'acme-aps' } })
    const request = { provider: 'aps', subject: { type: 'app' } } as const

    await source.getToken(request)
    await source.getToken({ ...request, forceRefresh: true })

    expect(mocks.getTokenResponse).toHaveBeenCalledTimes(2)
    expect(mocks.getTokenResponse).toHaveBeenLastCalledWith(
      'acme-aps',
      { subject: { type: 'app' } },
      { forceRefresh: true },
    )
  })

  it('throws not_configured for a provider without a connector', async () => {
    const source = connectTokenSource({ connectors: {} })

    await expect(
      source.getToken({ provider: 'aps', subject: { type: 'app' } }),
    ).rejects.toMatchObject({
      name: 'TokenError',
      code: 'not_configured',
      provider: 'aps',
    })
    expect(mocks.getTokenResponse).not.toHaveBeenCalled()
  })

  it('falls back to defaultTtlMs when the SDK response has no expiry', async () => {
    mocks.getTokenResponse.mockResolvedValue({ token: 'stk-no-expiry' })
    const source = connectTokenSource({ connectors: { aps: 'acme-aps' }, defaultTtlMs: 60_000 })
    const before = Date.now()

    const token = await source.getToken({ provider: 'aps', subject: { type: 'app' } })

    expect(token.expiresAt).toBeGreaterThanOrEqual(before + 60_000)
    expect(token.expiresAt).toBeLessThanOrEqual(Date.now() + 60_000)
  })

  it('maps SDK consent errors to TokenError consent_required', async () => {
    mocks.getTokenResponse.mockRejectedValue(
      new UserAuthorizationRequiredError('user must authorize first'),
    )
    const source = connectTokenSource({ connectors: { aps: 'acme-aps' } })

    await expect(
      source.getToken({ provider: 'aps', subject: { type: 'user', id: 'u1' } }),
    ).rejects.toMatchObject({ name: 'TokenError', code: 'consent_required', provider: 'aps' })
  })

  it('maps unknown SDK failures to provider_error', async () => {
    mocks.getTokenResponse.mockRejectedValue(new Error('boom'))
    const source = connectTokenSource({ connectors: { aps: 'acme-aps' } })

    await expect(
      source.getToken({ provider: 'aps', subject: { type: 'app' } }),
    ).rejects.toMatchObject({ name: 'TokenError', code: 'provider_error', provider: 'aps' })
  })
})
