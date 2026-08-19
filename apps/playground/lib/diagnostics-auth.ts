const encoder = new TextEncoder()

async function digest(value: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(value)))
}

async function safeEqual(left: string, right: string): Promise<boolean> {
  const [leftDigest, rightDigest] = await Promise.all([digest(left), digest(right)])
  let difference = 0
  for (let index = 0; index < leftDigest.length; index += 1) {
    difference |= (leftDigest[index] ?? 0) ^ (rightDigest[index] ?? 0)
  }
  return difference === 0
}

export async function isDiagnosticsAuthorized(request: Request): Promise<boolean> {
  const expected = process.env.PLAYGROUND_DIAGNOSTICS_TOKEN
  if (!expected) return false
  const authorization = request.headers.get('authorization')
  if (!authorization?.startsWith('Bearer ')) return false
  return safeEqual(authorization.slice('Bearer '.length), expected)
}
