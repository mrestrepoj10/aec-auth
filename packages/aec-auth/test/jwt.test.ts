import { createVerify, generateKeyPairSync } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { importRs256PrivateKey, signJwtRS256 } from '../src/internal/jwt'

function base64UrlDecode(segment: string): Uint8Array {
  const padded = segment.replace(/-/g, '+').replace(/_/g, '/')
  return Uint8Array.from(atob(padded), (ch) => ch.charCodeAt(0))
}

function decodeJson(segment: string): unknown {
  return JSON.parse(new TextDecoder().decode(base64UrlDecode(segment)))
}

function pemWrap(label: string, der: ArrayBuffer): string {
  const base64 = btoa(String.fromCharCode(...new Uint8Array(der)))
  const lines = base64.match(/.{1,64}/g) ?? []
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----\n`
}

async function generateWebCryptoKeyPair() {
  return crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
  )
}

describe('signJwtRS256', () => {
  it('signs a verifiable JWT from a PKCS#8 PEM and round-trips header and claims', async () => {
    const pair = await generateWebCryptoKeyPair()
    const pkcs8 = await crypto.subtle.exportKey('pkcs8', pair.privateKey)
    const pem = pemWrap('PRIVATE KEY', pkcs8)
    const claims = {
      iss: 'client-id',
      sub: 'SA1',
      aud: 'https://developer.api.autodesk.com/authentication/v2/token',
      exp: 1_700_000_300,
      scope: ['data:read', 'data:write'],
    }

    const jwt = await signJwtRS256({ kid: 'kid-1', privateKey: pem, claims })

    const segments = jwt.split('.')
    expect(segments).toHaveLength(3)
    const [header, payload, signature] = segments as [string, string, string]
    expect(decodeJson(header)).toEqual({ alg: 'RS256', kid: 'kid-1' })
    expect(decodeJson(payload)).toEqual(claims)
    const verified = await crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5',
      pair.publicKey,
      base64UrlDecode(signature) as BufferSource,
      new TextEncoder().encode(`${header}.${payload}`),
    )
    expect(verified).toBe(true)
  })

  it('accepts an already-imported CryptoKey', async () => {
    const pair = await generateWebCryptoKeyPair()
    const jwt = await signJwtRS256({
      kid: 'kid-2',
      privateKey: pair.privateKey,
      claims: { sub: 'SA2' },
    })
    const [header, payload, signature] = jwt.split('.') as [string, string, string]
    expect(decodeJson(header)).toEqual({ alg: 'RS256', kid: 'kid-2' })
    const verified = await crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5',
      pair.publicKey,
      base64UrlDecode(signature) as BufferSource,
      new TextEncoder().encode(`${header}.${payload}`),
    )
    expect(verified).toBe(true)
  })

  it('signs from the PKCS#1 PEM shape APS returns for SSA keys', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
      publicKeyEncoding: { type: 'spki', format: 'pem' },
    })
    expect(privateKey).toContain('BEGIN RSA PRIVATE KEY')

    const jwt = await signJwtRS256({ kid: 'kid-3', privateKey, claims: { sub: 'SA3' } })

    const [header, payload, signature] = jwt.split('.') as [string, string, string]
    const verify = createVerify('RSA-SHA256')
    verify.update(`${header}.${payload}`)
    expect(verify.verify(publicKey, Buffer.from(base64UrlDecode(signature)))).toBe(true)
  })

  it('normalizes literal \\n sequences (keys pasted from JSON or env vars)', async () => {
    const pair = await generateWebCryptoKeyPair()
    const pkcs8 = await crypto.subtle.exportKey('pkcs8', pair.privateKey)
    const escaped = pemWrap('PRIVATE KEY', pkcs8).replace(/\n/g, '\\n')

    const jwt = await signJwtRS256({ kid: 'kid-4', privateKey: escaped, claims: { sub: 'SA4' } })

    const [header, payload, signature] = jwt.split('.') as [string, string, string]
    const verified = await crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5',
      pair.publicKey,
      base64UrlDecode(signature) as BufferSource,
      new TextEncoder().encode(`${header}.${payload}`),
    )
    expect(verified).toBe(true)
  })
})

describe('importRs256PrivateKey', () => {
  it('rejects garbage PEM input', async () => {
    const garbage = `-----BEGIN PRIVATE KEY-----\n${btoa('not a key at all')}\n-----END PRIVATE KEY-----`
    await expect(importRs256PrivateKey(garbage)).rejects.toThrow()
  })
})
