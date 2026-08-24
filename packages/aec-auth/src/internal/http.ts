/**
 * Rate-limit retry plumbing shared by the APS clients (`aec-auth` internal).
 * APS signals rate limiting with `HTTP 429` and (usually) a `Retry-After`
 * header in seconds; there are no `X-RateLimit-*` budget headers, so reactive
 * backoff is the only strategy.
 */

export const RATE_LIMIT_RETRIES = 3
export const RATE_LIMIT_BASE_MS = 1_000
export const RATE_LIMIT_MAX_WAIT_MS = 30_000

/** Delay before retrying a 429: `Retry-After` (seconds, per APS docs) when present and sane, else jittered exponential backoff. Always capped. */
export function rateLimitDelayMs(response: Response, attempt: number): number {
  const header = response.headers.get('retry-after')
  if (header !== null) {
    const seconds = Number(header)
    if (Number.isFinite(seconds) && seconds >= 0) {
      return Math.min(seconds * 1000, RATE_LIMIT_MAX_WAIT_MS)
    }
    const dateMs = Date.parse(header) - Date.now() // RFC 9110 also allows an HTTP-date
    if (Number.isFinite(dateMs) && dateMs > 0) return Math.min(dateMs, RATE_LIMIT_MAX_WAIT_MS)
  }
  const backoff = RATE_LIMIT_BASE_MS * 2 ** attempt
  return Math.min(backoff + Math.random() * backoff, RATE_LIMIT_MAX_WAIT_MS)
}

/** Streams can't be replayed; only absent or string bodies are safe to retry. */
export function isRetryableBody(body: BodyInit | null | undefined): boolean {
  return body === undefined || body === null || typeof body === 'string'
}

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}
