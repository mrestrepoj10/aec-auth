import type { IAuthenticationProvider } from '@aps_sdk/autodesk-sdkmanager'
import { describe, expect, it } from 'vitest'
import { apsAuthenticationProvider } from '../src/aps'
import type { TokenRequest } from '../src/index'
import { mockTokenSource } from '../src/mock'

describe('apsAuthenticationProvider (official @aps_sdk interop)', () => {
  it('satisfies the SDK IAuthenticationProvider contract at the type level', () => {
    // Structural typing is the whole interop claim: assignment compiles only
    // if the adapter matches the SDK interface exactly.
    const provider: IAuthenticationProvider = apsAuthenticationProvider(mockTokenSource(), {
      subject: { type: 'app' },
    })
    expect(typeof provider.getAccessToken).toBe('function')
  })

  it('returns the raw token string for the configured subject', async () => {
    const provider = apsAuthenticationProvider(mockTokenSource(), {
      subject: { type: 'user', id: 'u1' },
    })
    await expect(provider.getAccessToken()).resolves.toMatch(/^mock-aps-user:u1/)
  })

  it('forwards SDK-requested scopes, falling back to configured then default scopes', async () => {
    const seen: Array<readonly string[] | undefined> = []
    const recording = {
      async getToken(request: TokenRequest) {
        seen.push(request.scopes)
        return mockTokenSource().getToken(request)
      },
    }

    const withDefaults = apsAuthenticationProvider(recording, { subject: { type: 'app' } })
    await withDefaults.getAccessToken()
    await withDefaults.getAccessToken(['viewables:read'])

    const withConfigured = apsAuthenticationProvider(recording, {
      subject: { type: 'app' },
      scopes: ['bucket:read'],
    })
    await withConfigured.getAccessToken()
    await withConfigured.getAccessToken([])

    expect(seen).toEqual([['data:read'], ['viewables:read'], ['bucket:read'], ['bucket:read']])
  })
})
