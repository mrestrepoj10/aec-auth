/**
 * Minimal RS256 JWT signing over WebCrypto (`aec-auth` internal). Exists for
 * the SSA jwt-bearer flow; deliberately not a general JWT library — no
 * verification, no other algorithms, no claim validation.
 */
const encoder = new TextEncoder()

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function base64UrlJson(value: unknown): string {
  return base64UrlEncode(encoder.encode(JSON.stringify(value)))
}

function decodeBase64(text: string): Uint8Array {
  return Uint8Array.from(atob(text), (ch) => ch.charCodeAt(0))
}

/** DER definite-length encoding. */
function derLength(length: number): number[] {
  if (length < 0x80) return [length]
  const bytes: number[] = []
  for (let remaining = length; remaining > 0; remaining >>= 8) bytes.unshift(remaining & 0xff)
  return [0x80 | bytes.length, ...bytes]
}

// PKCS#8 PrivateKeyInfo prefix for RSA: INTEGER 0, then
// SEQUENCE { OID 1.2.840.113549.1.1.1 (rsaEncryption), NULL }.
const RSA_PKCS8_HEADER = [
  0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
  0x05, 0x00,
]

/**
 * Wraps a PKCS#1 RSAPrivateKey in a PKCS#8 PrivateKeyInfo envelope. APS
 * returns SSA keys as PKCS#1 PEM (`BEGIN RSA PRIVATE KEY`), which WebCrypto
 * cannot import directly.
 */
function pkcs1ToPkcs8(pkcs1: Uint8Array): Uint8Array {
  const octetStringHeader = [0x04, ...derLength(pkcs1.length)]
  const contentLength = RSA_PKCS8_HEADER.length + octetStringHeader.length + pkcs1.length
  const out = [0x30, ...derLength(contentLength), ...RSA_PKCS8_HEADER, ...octetStringHeader]
  const bytes = new Uint8Array(out.length + pkcs1.length)
  bytes.set(out)
  bytes.set(pkcs1, out.length)
  return bytes
}

/**
 * Imports an RSA private key PEM for RS256 signing. Accepts PKCS#8
 * (`BEGIN PRIVATE KEY`) and the PKCS#1 (`BEGIN RSA PRIVATE KEY`) that the
 * SSA Create Key operation returns; literal `\n` sequences (keys pasted
 * from JSON or env vars) are normalized to newlines first.
 */
export async function importRs256PrivateKey(pem: string): Promise<CryptoKey> {
  const normalized = pem.replace(/\\n/g, '\n')
  const pkcs1 = /-----BEGIN RSA PRIVATE KEY-----/.test(normalized)
  const body = normalized
    .replace(/-----(BEGIN|END)[A-Z ]*PRIVATE KEY-----/g, '')
    .replace(/\s+/g, '')
  const der = decodeBase64(body)
  return crypto.subtle.importKey(
    'pkcs8',
    (pkcs1 ? pkcs1ToPkcs8(der) : der) as BufferSource,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign'],
  )
}

/** Signs `claims` as an RS256 JWT with header `{ alg: 'RS256', kid }`. */
export async function signJwtRS256(options: {
  kid: string
  privateKey: CryptoKey | string
  claims: Record<string, unknown>
}): Promise<string> {
  const key =
    typeof options.privateKey === 'string'
      ? await importRs256PrivateKey(options.privateKey)
      : options.privateKey
  const signingInput = `${base64UrlJson({ alg: 'RS256', kid: options.kid })}.${base64UrlJson(options.claims)}`
  const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, encoder.encode(signingInput))
  return `${signingInput}.${base64UrlEncode(new Uint8Array(signature))}`
}
