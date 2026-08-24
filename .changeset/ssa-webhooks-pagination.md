---
'aec-auth': patch
---

Secure Service Accounts (SSA) as a third token subject, plus the supporting client work.

- `TokenSubject` gains `{ type: 'service_account'; id }`, minted through the vault via the
  APS jwt-bearer grant (signed RS256 assertion, no refresh token). Consumers that switch
  exhaustively on `subject.type` gain a new case at compile time.
- `apsOAuth` accepts `serviceAccountKeys`; Vercel Connect rejects service-account subjects
  with a typed `not_configured` explaining why (its custom OAuth cannot sign assertions).
- The APS client now retries `429` honoring `Retry-After`.
- New: `apsPaginate` (from `aec-auth/aps`), `aec-auth/webhooks`, `aec-auth/ssa`.
