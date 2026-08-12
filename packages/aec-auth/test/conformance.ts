import { expect } from 'vitest'
import { isExpired, type TokenRequest, type TokenSource } from '../src/index'

/**
 * Behavioral assertions every TokenSource implementation must satisfy. Each
 * backend's suite (and any future backend, including user-written ones) runs
 * this against a configured instance so "works as expected" means the same
 * thing everywhere.
 */
export async function runTokenSourceConformance(
  source: TokenSource,
  base: Omit<TokenRequest, 'forceRefresh'>,
): Promise<void> {
  const first = await source.getToken({ ...base })
  expect(first.token).toBeTypeOf('string')
  expect(first.token.length).toBeGreaterThan(0)
  expect(first.expiresAt).toBeTypeOf('number')
  expect(isExpired(first)).toBe(false)

  const second = await source.getToken({ ...base })
  expect(second.token.length).toBeGreaterThan(0)
  expect(isExpired(second)).toBe(false)

  const concurrent = await Promise.all([
    source.getToken({ ...base }),
    source.getToken({ ...base }),
    source.getToken({ ...base }),
  ])
  for (const token of concurrent) expect(isExpired(token)).toBe(false)

  const forced = await source.getToken({ ...base, forceRefresh: true })
  expect(forced.token.length).toBeGreaterThan(0)
  expect(isExpired(forced)).toBe(false)

  const afterForce = await source.getToken({ ...base })
  expect(isExpired(afterForce)).toBe(false)
}
