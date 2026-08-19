# Vulnerability Scan Report

| Field | Value |
|-------|-------|
| Project | aec-auth |
| Date | 2026-08-18T15:51:06.056Z |
| Files tracked | 36 |
| Files analyzed | 36 |
| Total findings | 12 |

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 0 |
| MEDIUM | 9 |
| HIGH_BUG | 2 |
| BUG | 1 |

## MEDIUM (9)

### CI executes GitHub Actions through mutable major-version tags

- **File:** `.github/workflows/ci.yml`
- **Recent committers:** MR <mrestrepoj10@gmail.com>
- **Lines:** 12, 13, 14
- **Slug:** other-supply-chain
- **Confidence:** high
- **Revalidation:** confirmed
- **Reasoning:** Accurate as written: lines 12-14 reference `actions/checkout@v4`, `pnpm/action-setup@v4`, and `actions/setup-node@v4`, all mutable major-version tags rather than immutable commit SHAs, and the workflow declares no `permissions:` block and does not set `persist-credentials: false`. A compromise of any of those action repositories or a maintainer account lets an attacker retarget the tag and execute arbitrary code in this workflow; after `checkout` the default-persisted Git credential and the ambient `GITHUB_TOKEN` are available to that code. I weighed the mitigating context: the workflow references no repository secrets, performs no publish or deploy, and fork `pull_request` runs get a read-only token with no secrets — so the realistic blast radius on push builds is token exfiltration and repository writes (including poisoning `main` and the built `dist/` of a package that handles OAuth secrets), not immediate credential theft. That is materially less than a critical finding but still a real, industry-standard supply-chain exposure with a concrete attack path, so I leave MEDIUM rather than adjusting; the recommendation to SHA-pin, add `permissions: contents: read`, and disable credential persistence is correct and cheap.

All three actions are referenced by mutable v4 tags rather than immutable commit SHAs. If an action repository or maintainer account is compromised, an attacker can move the referenced tag and execute arbitrary code in CI. This is especially consequential after checkout because credentials are persisted by default, and push builds may also expose repository secrets or a GITHUB_TOKEN whose effective permissions depend on repository settings.

**Recommendation:** Pin every action to a reviewed full commit SHA and use dependency automation to update those pins. Also declare minimal workflow permissions, such as `permissions: { contents: read }`, and set `persist-credentials: false` on checkout unless later steps require Git authentication.

---

### Unauthenticated diagnostics endpoint triggers paid and credentialed provider operations

- **File:** `apps/playground/app/api/token/route.ts`
- **Recent committers:** MR <mrestrepoj10@gmail.com>
- **Lines:** 3, 6, 7
- **Slug:** expensive-api-abuse
- **Confidence:** high
- **Revalidation:** confirmed
- **Reasoning:** I read apps/playground/app/api/token/route.ts in full: it is a nine-line GET handler that imports runChecks from ../../../lib/checks, sets `export const dynamic = 'force-dynamic'`, and unconditionally awaits runChecks() before serializing the result. There is no handler-local auth check, no session read, no rate limiter, and no Cache-Control header. I searched the whole repo for middleware.ts and found none, so Next.js applies no route protection above this handler; the layout.tsx is purely presentational. Tracing runChecks (lib/checks.ts:145-153), each invocation runs all six checks in parallel, and two of them perform real credentialed network work when env is present: checkVaultRealAps (lines 91-112) constructs a *fresh* memoryVaultStore + vaultTokenSource per call with APS_CLIENT_ID/SECRET, mints a client-credentials token, and calls the live Model Derivative formats endpoint; checkConnect (114-128) builds a fresh connectTokenSource and requests a Vercel Connect token, which is a billed per-request operation. Because the store and cache are created inside the function body, nothing is reused across requests, so caching cannot damp the load — the finding's core technical claim is exactly right. Concrete attack: if this app is deployed publicly, an attacker loops GET /api/token and each request forces a new APS token grant, a live APS API call, and a paid Connect token request, consuming quota, incurring cost, and potentially tripping APS rate limits that degrade the real integration. The one mitigating context is that apps/playground is `private: true` with no vercel.json and README (lines 122-132) documents it as a localhost `pnpm --filter playground dev` demo, so no deployed instance exists in-repo; that bounds impact but does not make the pattern safe, and the project threat model explicitly lists this as a pattern to flag. MEDIUM is appropriate given the conditional (deployment-dependent) exploitability.

Every unauthenticated GET executes runChecks(), and force-dynamic prevents static caching. The imported implementation creates fresh token sources on each invocation, obtains a real APS client-credentials token, calls the Model Derivative API, and requests a Vercel Connect token when the corresponding environment variables exist. Vercel Connect bills per token request, and the newly constructed source cannot reuse its cache across requests. An attacker can repeatedly request this endpoint to consume provider quotas, incur costs, and degrade service availability. No handler-local authentication, authorization, throttling, or response caching is present.

**Recommendation:** Disable this development endpoint in production or protect it with handler-local authentication. Add rate limiting and cache/coalesce check results so public requests cannot initiate provider operations. Prefer running live checks from an authenticated administrative or scheduled health-check path.

---

### Public diagnostics response exposes provider errors and integration metadata

- **File:** `apps/playground/app/api/token/route.ts`
- **Recent committers:** MR <mrestrepoj10@gmail.com>
- **Lines:** 6, 7, 9
- **Slug:** other-info-disclosure
- **Confidence:** high
- **Revalidation:** confirmed
- **Reasoning:** This is a distinct vulnerability class from F1 at the same location (abuse-of-function vs. information disclosure), so it is not a duplicate. The handler returns `Response.json({ ok: !failed, checks })` — the entire Check[] array, including each check's `detail`, with no redaction or field filtering. Tracing detail population in lib/checks.ts: the `failed()` helper (lines 28-35) assigns `error instanceof Error ? error.message : String(error)` verbatim. I followed that message to its source in packages/aec-auth/src/aps.ts:113-118, where requestJson appends the raw upstream response body to the error text (`APS request ${path} failed with ${status} ${statusText}: ${body}`), so genuine APS error payloads are reflected to the client. On success paths the details are equally revealing: line 85 interpolates the configured APS_EMULATOR_URL (an internal origin), line 124 interpolates the APS_CONNECTOR identifier, lines 84/123 disclose exact token TTLs, and line 108 discloses live API result counts. The skipped-vs-pass status matrix itself enumerates which credential-bearing integrations are configured, letting an unauthenticated requester fingerprint credential state. No secrets (client secret, bearer token) are exposed — checkMock truncates its mock token to 24 chars and real tokens are never rendered — so this is reconnaissance-grade disclosure rather than direct credential leakage, which matches the MEDIUM rating. Exploitability again depends on the playground being deployed beyond localhost, but the code as written has no authorization gate whatsoever, so the finding and its recommendation stand.

The route returns the complete checks array to any requester. runChecks() places caught Error.message values directly into each check's detail and successful checks disclose the configured APS emulator URL, Vercel connector identifier, token lifetime, and live API result counts. This lets an unauthenticated attacker enumerate enabled integrations and credential state, discover internal emulator/service origins, and obtain raw APS or Vercel error details useful for infrastructure reconnaissance.

**Recommendation:** Require authentication for detailed diagnostics. Return only a minimal generic health status publicly, keep provider errors and configuration identifiers in server-side logs, and explicitly redact secrets, URLs, connector identifiers, and upstream response bodies.

---

### Unauthenticated page triggers credentialed provider operations on every request

- **File:** `apps/playground/app/page.tsx`
- **Recent committers:** MR <mrestrepoj10@gmail.com>
- **Lines:** 3, 8, 9
- **Slug:** expensive-api-abuse
- **Confidence:** high
- **Revalidation:** confirmed
- **Reasoning:** apps/playground/app/page.tsx is a `force-dynamic` async Server Component whose first statement is `const checks = await runChecks()`. I read the whole file: there is no auth import, no session/cookie inspection, no redirect guard, and no caching directive other than force-dynamic which actively disables it. layout.tsx wraps it with styling only, and there is no middleware.ts anywhere in the repo, so every anonymous GET of `/` executes the full check suite server-side. The cited line numbers in checks.ts are accurate: checkVaultRealAps at 91-112 mints a real APS client-credentials token from APS_CLIENT_ID/APS_CLIENT_SECRET into a freshly constructed memoryVaultStore and issues a live Model Derivative request; checkConnect at 114-126 requests a billed Vercel Connect token when APS_CONNECTOR is set. The fresh-per-invocation construction of both token sources means the caches in withTokenCache/vaultTokenSource cannot deduplicate across renders — the reuse argument that would defeat this finding does not apply. Attack: repeated page loads (trivially automated, and amplified by any crawler or preview-image fetcher) drive one token grant plus one live API call plus one paid Connect token per request. This is the same class of issue as F1 but at a different code location (page render path vs. route handler), and the duplicate rules explicitly state that same class in a different location is not a duplicate, so it keeps its own verdict. Mitigating context, as with F1: the app is private, undeployed, and README-documented as a localhost dev tool, which caps real-world impact and justifies keeping severity at MEDIUM rather than raising it.

The force-dynamic page invokes runChecks() for every anonymous HTTP request without authentication or rate limiting. The imported suite creates a fresh in-memory vault and uses APS_CLIENT_ID/APS_CLIENT_SECRET to mint a client-credentials token and call the live APS Model Derivative API (apps/playground/lib/checks.ts lines 91-110). It also requests a Vercel Connect token when APS_CONNECTOR is configured (lines 114-126). Because these token sources and their caches are recreated inside every runChecks invocation, requests do not reuse tokens across page renders. An attacker can repeatedly request the page to generate paid Connect operations, consume APS quotas, and cause provider throttling or service degradation.

**Recommendation:** Keep the playground development-only. If it is deployed, wrap the page with direct session or administrative authorization and enforce per-principal and per-IP rate limits. Persist/reuse token sources outside the request lifecycle and consider replacing active provider checks with a scheduled, cached health result.

---

### Public diagnostics expose provider configuration and raw upstream errors

- **File:** `apps/playground/app/page.tsx`
- **Recent committers:** MR <mrestrepoj10@gmail.com>
- **Lines:** 14, 15, 37
- **Slug:** other-info-disclosure
- **Confidence:** high
- **Revalidation:** confirmed
- **Reasoning:** Separate vulnerability class from F3 at the same location (disclosure vs. abuse), therefore not a duplicate. I verified the rendering path: the table body maps over checks and emits `{check.name}`, `{check.how}`, the status label, and — in the final cell — `{check.detail}` unmodified. React escapes HTML (so this is not XSS) but does not redact content, so whatever runChecks put in `detail` reaches any visitor's browser. I confirmed each cited source: failed() at checks.ts:28-34 copies Error.message verbatim, and that message can embed the raw APS response body via packages/aec-auth/src/aps.ts:115-118; pass() details at line 85 leak the configured APS_EMULATOR_URL and at line 124 the APS_CONNECTOR identifier, plus token TTLs and live format counts. The skip messages additionally enumerate exactly which env vars are unset (lines 75, 97, 119), giving an attacker a precise map of which integrations are configured versus dormant. The `how` column also names each backend module. No access-control check exists between this data and an anonymous requester. Impact is reconnaissance rather than direct secret theft — no client secret, refresh token, or full access token is rendered — which is consistent with MEDIUM. As with the other three, actual exploitation requires the playground to be publicly served, which the repo does not itself do, but the code contains no mitigation and the project's own threat model flags this exact behavior.

The page renders check.detail directly to every visitor. runChecks populates this field with unfiltered Error.message values, including APS response bodies and Vercel Connect errors (apps/playground/lib/checks.ts lines 28-34), and successful checks disclose the configured emulator URL and Vercel connector identifier (lines 85 and 124). The matrix also reveals which credential-bearing integrations are configured. An unauthenticated attacker can use these implementation details and provider errors to map the deployment and assist targeted attacks.

**Recommendation:** Do not expose detailed diagnostics publicly. Require administrative authorization, return only coarse health states to clients, and send sanitized detailed errors to protected server-side telemetry. Remove connector identifiers, configured URLs, and raw provider messages from rendered output.

---

### Unauthenticated diagnostics repeatedly invoke credential-backed services

- **File:** `apps/playground/lib/checks.ts`
- **Recent committers:** MR <mrestrepoj10@gmail.com>
- **Lines:** 33, 74, 85, 94, 95, 101, 103, 105, 117, 121, 124, 145
- **Slug:** expensive-api-abuse
- **Confidence:** high
- **Revalidation:** confirmed
- **Reasoning:** Traced both ingress points and they match the finding. `apps/playground/app/page.tsx` and `app/api/token/route.ts` are each `export const dynamic = 'force-dynamic'` and call `runChecks()` directly with no auth check, no middleware (no middleware file exists in the app), and no rate limiting. Inside `runChecks`, `checkVaultRealAps` builds a *fresh* `memoryVaultStore()` per invocation (checks.ts:99-101), so caching cannot amortize anything: every request mints a new real APS client-credentials token and makes a live Model Derivative `/designdata/formats` call, `checkVaultEmulator` mints another token against `APS_EMULATOR_URL`, and `checkConnect` requests a token from Vercel Connect (121-122), which is the per-request-billed path the library's own docs warn to keep behind a cache. Information disclosure is also real: `pass` details echo the configured emulator base URL (85) and the connector identifier (124), skip messages reveal which secrets are configured (75, 97, 119), and `failed` returns raw provider error text via `error.message` (33), which for `apsOAuth` includes the APS token endpoint status and `error_description`. Exposure is conditional on deployment — the checks skip cleanly when env is absent, and the README frames the playground as a local `pnpm --filter playground dev` app — but the same README explicitly tells readers to copy `lib/checks.ts` plus the route handler into their own Next.js app as a starting point, which propagates an unauthenticated, uncached, credential-backed endpoint. MEDIUM is fair; keep it dev-only or gate and sanitize it.

runChecks is called by both the public server-rendered playground page and the unauthenticated, force-dynamic /api/token handler. Each invocation creates a fresh in-memory vault, obtains a real APS client-credentials token, calls the Model Derivative API, and requests another token from Vercel Connect. Because the token sources and caches are recreated per request, repeated requests cannot reuse prior tokens and can generate provider traffic or connector charges without authentication or rate limiting. The returned details also expose configured emulator URLs, connector identifiers, secret-presence state, and raw provider error messages.

**Recommendation:** Keep these checks development-only or directly protect every calling route with authentication. Add rate limiting, reuse long-lived token sources where appropriate, and return only coarse health status while logging sanitized diagnostic details privately.

---

### Ambiguous cache keys can return another user's bearer token

- **File:** `packages/aec-auth/src/index.ts`
- **Recent committers:** MR <mrestrepoj10@gmail.com>
- **Lines:** 70, 71, 75, 76, 77, 97, 99, 100
- **Slug:** cache-key-poisoning
- **Confidence:** high
- **Revalidation:** confirmed
- **Reasoning:** The ambiguity is real and verified in current code: `subjectKey` (line 71) interpolates the raw user id into `user:${id}` and `requestKey` (lines 76-77) joins provider, subject key, and space-joined sorted scopes with `:` and no escaping or length prefixing. The stated collision holds exactly — `{id:'victim', scopes:['data:read']}` and `{id:'victim:data', scopes:['read']}` both serialize to `aps:user:victim:data:read`. This key is the sole identity for both the in-process `fresh` map in `withTokenCache` (line 99) and the persisted vault token key (`tokenKey` -> `aec-auth:token:<requestKey>` in vault.ts), so a colliding request receives a cached bearer token minted for a different subject/scope set before any provider validation occurs. The vault's grant existence check only proves the *attacker's* id has a grant; the cached-token fast path at vault.ts:381 returns before any grant check at all, so a colliding attacker id would not even need a grant when a victim token is warm. I downgrade HIGH to MEDIUM because exploitation requires the deployment's user identifiers (or requested scopes) to be attacker-influenced strings containing `:`; the in-repo consumers use fixed scope recipes (`apsScopes.dataRead`) and Better Auth/APS identifiers are opaque and colon-free, so no repository code path is itself exploitable. It remains a genuine library defect: `aec-auth` is a published package that accepts arbitrary caller-supplied ids and cannot validate them, and the failure mode is cross-subject token disclosure rather than a mere cache miss. The recommended structured/length-prefixed encoding is correct.

`subjectKey` embeds an unrestricted user ID directly, while `requestKey` concatenates that value and the space-joined scopes using `:` without escaping or length-prefixing. Distinct requests can therefore have identical keys. For example, `{id:'victim', scopes:['data:read']}` and `{id:'victim:data', scopes:['read']}` both produce `aps:user:victim:data:read`. If the victim's token is already cached, `withTokenCache` returns it before the upstream provider can reject the attacker's invalid scope. In an integration where authenticated user IDs or requested scopes are attacker-influenced, this causes cross-user token disclosure or impersonation. The same key helper is also used by the persistent vault cache.

**Recommendation:** Use an unambiguous structured encoding, such as JSON serialization of `[provider, subject.type, subject.id ?? null, sortedScopes]`, or length-prefix/hash each component. Explicitly distinguish absent and empty scope lists if they have different semantics, and add collision tests using delimiter-containing IDs and malformed scopes.

---

### Public OAuth clients are permitted to operate without PKCE

- **File:** `packages/aec-auth/src/internal/oauth.ts`
- **Recent committers:** MR <mrestrepoj10@gmail.com>
- **Lines:** 30, 38, 169, 189, 197, 216
- **Slug:** other-oauth-code-interception
- **Confidence:** high
- **Revalidation:** ~~false positive~~
- **Reasoning:** The code reads as described — `codeChallenge` (line 30) and `codeVerifier` (line 38) are optional, `buildAuthorizeUrl` only emits `code_challenge`/`code_challenge_method` when a challenge is supplied (141-144), and `exchangeCode` passes `code_verifier: undefined` through `formBody`, which drops undefined fields (70-76) — but this is a pass-through API surface, not an exploitable defect. There is no attacker-controlled input and no code path where the library weakens or strips protection the caller asked for: it faithfully forwards whatever PKCE material it is given, and it always uses S256 (never `plain`) when a challenge is present. Nothing in this repository constructs a PKCE-less public client. `apsOAuth`'s only in-repo callers pass a `clientSecret` and are therefore confidential clients (`examples/aps-3legged.mjs:52`, `apps/playground/lib/checks.ts:80,101`), `clientCredentials` hard-fails without a secret (176-181), and the Better Auth glue sets `pkce: true` unconditionally (`src/betterauth.ts:41`), which the test suite asserts along with `code_challenge=` in the authorize URL. Realizing the described code-interception attack requires a downstream integrator to independently choose to build a public-client authorization flow and omit the challenge — their vulnerability, and one the fixed production APS endpoint would likely reject for a secretless client anyway. Requiring an S256 challenge whenever `clientSecret` is absent, and shipping a verifier-generation helper, are legitimate secure-default hardening suggestions and worth doing, but they do not describe a real, exploitable vulnerability in this codebase, so MEDIUM is not warranted.

When clientSecret is absent, apsOAuth explicitly configures a public client, but both codeChallenge and codeVerifier remain optional. authorizeUrl therefore permits an authorization request without an S256 challenge, and exchangeCode silently omits the verifier. A public or native integration can consequently create a bearer authorization-code flow with no proof binding the code to the client instance. An attacker who intercepts a code, particularly through a custom URI-scheme collision or another compromised redirect channel, can redeem it and obtain the victim's APS tokens. Confidential-client flows using a protected client secret are not affected in the same way.

**Recommendation:** When clientSecret is absent, require a nonempty S256 codeChallenge in authorizeUrl and a matching, syntactically valid codeVerifier in exchangeCode. Consider exposing a helper that securely generates and hashes verifiers so public-client callers cannot accidentally disable PKCE.

---

### Grant deletion does not revoke cached or in-flight credentials

- **File:** `packages/aec-auth/src/vault.ts`
- **Recent committers:** MR <mrestrepoj10@gmail.com>
- **Lines:** 228, 233, 304, 309, 380, 382
- **Slug:** other-revocation-bypass
- **Confidence:** high
- **Revalidation:** confirmed
- **Reasoning:** Verified: `deleteUserGrant` (vault.ts:228-234) issues a single `store.delete(grantKey(...))` and touches nothing else. Meanwhile `vaultTokenSource.getToken` reads and returns the cached access token at lines 380-382 *before* `acquireAndMint` performs its grant-existence check (322-331), so after a documented sign-out/revocation the previously cached bearer token continues to be handed out for the remainder of its TTL (`writeToken` sets the store TTL to the token's own expiry, roughly an APS access-token hour). Nothing enumerates or deletes the per-scope `aec-auth:token:aps:user:<id>:<scopes>` keys, and there is no scope enumeration available to do so, so the library offers no way for a caller to clear them either. The resurrection path is also real: deletion takes no lock and there is no generation/tombstone, so a refresh already inside `mintUnderLock` can complete and `saveUserGrant` at 309-313 recreates a grant for a user whose consent was just revoked, restoring indefinite refresh capability rather than just a short-lived token. Combined, a stolen session, a queued background job, or an in-flight concurrent request can keep acting as the user after revocation was supposed to take effect. MEDIUM is the right severity: it requires an already-provisioned grant and a revocation event, and bearer tokens are inherently valid until expiry absent provider-side revocation — but the grant recreation goes beyond that inherent limit, so this is a genuine gap, not accepted behavior.

deleteUserGrant deletes only the refresh-grant key. vaultTokenSource checks and returns a cached access token before confirming that a user grant still exists, so disconnecting or deprovisioning a user can leave usable APS bearer tokens available until they expire. Deletion is also not coordinated with the subject's refresh lock: a refresh that began before deletion can subsequently persist its rotated refresh token and recreate the deleted grant. An application relying on this documented sign-out/revocation operation can therefore continue acting through a stolen session, background task, or concurrent request after access was supposed to be removed.

**Recommendation:** Make revocation atomic with refresh. Acquire the same subject lock or use a persistent revocation generation/tombstone, verify that generation before saving a rotated grant, and prevent cached user tokens from being returned after deletion. Track and delete all per-scope token keys for the subject, or bind each cached token to the current grant generation.

---

## HIGH_BUG (2)

### Forced refreshes bypass single-flight and race cache ownership

- **File:** `packages/aec-auth/src/index.ts`
- **Recent committers:** MR <mrestrepoj10@gmail.com>
- **Lines:** 86, 87, 88, 89, 98, 101, 104, 107, 110, 111, 113
- **Slug:** other-race-condition
- **Confidence:** high
- **Revalidation:** confirmed
- **Reasoning:** Confirmed by reading index.ts:96-114. When `forceRefresh` is set, the whole guard block (98-103) is skipped, so the existing `inflight` promise is neither consulted nor awaited, and a second upstream call starts for the same key. Line 113 then unconditionally overwrites the map entry, and the `.finally` at 110-112 unconditionally does `inflight.delete(key)` with no ownership check — so whichever call settles first evicts the *other* call's marker, and a subsequent non-forced caller sees an empty `inflight` and issues a third upstream request. Line 107 likewise writes to `fresh` unconditionally, so an older, slower completion can clobber a newer token, leaving the cache serving a token that the provider may have already superseded. That the identical pattern in vault.ts:386-388 *does* guard cleanup with `if (inflight.get(key) === run)` confirms this is an oversight in index.ts rather than intended semantics. The trigger is reachable and not theoretical: `createApsClient.requestJson` (aps.ts) retries every 401 with `forceRefresh: true`, so a batch of concurrent APS calls whose cached token has just been invalidated produces simultaneous forced refreshes through the same wrapper. Against a source that rotates single-use refresh tokens (apsOAuth via the vault, or a bare vault-less source) or a per-request-billed source (connectTokenSource), that means duplicate rotations and grant-family invalidation or extra provider cost. HIGH_BUG is appropriate for a correctness/race defect in the exact component documented as the protection against this failure mode.

When `forceRefresh` is true, the wrapper skips the existing in-flight promise and starts another upstream request for the same key. It then overwrites the `inflight` entry, while every request unconditionally deletes that entry on completion and writes its result to `fresh`. Concurrent forced refreshes can therefore call the provider simultaneously, let an older completion overwrite a newer token, and let one completion delete another request's in-flight marker. This is especially serious for the rotating OAuth sources the wrapper is documented to protect: simultaneous 401 retries can replay a single-use APS refresh token and invalidate the grant family, requiring user re-consent.

**Recommendation:** Serialize forced refreshes per cache key or maintain a dedicated forced-refresh single-flight. Guard cleanup with `if (inflight.get(key) === upstream)` and use a generation/ownership check so older requests cannot overwrite newer cached results. Add tests for overlapping normal and forced calls, multiple forced calls, rejection ordering, and out-of-order completion.

---

### Unrenewed refresh lease can destroy a single-use grant family

- **File:** `packages/aec-auth/src/vault.ts`
- **Recent committers:** MR <mrestrepoj10@gmail.com>
- **Lines:** 236, 304, 337, 346, 350
- **Slug:** other-race-condition
- **Confidence:** high
- **Revalidation:** confirmed
- **Reasoning:** Confirmed against the code: `LOCK_TTL_MS = 10_000` (line 236) is passed once to `store.acquireLock` (337) and never renewed; the `VaultStore` interface (36-52) exposes no renewal primitive at all, so no implementation could heartbeat it. The critical section held under that lease spans `readToken`, `readGrant`, a network `oauth.refresh`, `saveUserGrant`, and `writeToken` (342-348) — an unbounded wall-clock window in serverless runtimes subject to cold starts, event-loop stalls, and slow APS token-endpoint responses. Because losing callers give up after only `WAIT_TIMEOUT_MS = 2_000` rather than waiting out the lock, a request arriving after the 10s TTL lapses will successfully acquire the *same* lock while the original holder is still inside `oauth.refresh`, re-read the un-rotated stored refresh token, and submit it a second time. APS refresh tokens are single-use, and the package's own README describes replay as bricking the grant until re-consent. `releaseLock`'s owner check (350, and memoryVaultStore:85-87) is genuinely safe against deleting a successor's lock, but as the finding says it does nothing to prevent the overlapping critical sections, and there is no fencing token or compare-and-set on `saveUserGrant`, so a stale holder's write can also clobber the newer grant. HIGH_BUG stands: no attacker action is required, only latency, and the impact is loss of the user's grant.

The distributed refresh lock has a fixed 10-second TTL and is never renewed or fenced. If the OAuth request, persistence operation, or runtime stall lasts longer than that, another process can acquire the expired lock and reread the same stored refresh token while the original holder remains active. Both processes can then submit the single-use token. APS treats replay as invalid and may invalidate the entire refresh-token family, leaving the stored replacement unusable. Owner-checked release only prevents the first process from deleting the second process's lock; it does not prevent the overlapping critical sections.

**Recommendation:** Add an atomic owner-checked lease-renewal operation and heartbeat for the full refresh-and-persist critical section. Stop publishing results if lease ownership is lost, and use a grant version/fencing token with compare-and-set persistence so stale holders cannot overwrite newer state. Make timing configurable, but do not rely solely on a longer fixed TTL.

---

## BUG (1)

### Concurrent forceRefresh can return the stale cached token

- **File:** `packages/aec-auth/src/vault.ts`
- **Recent committers:** MR <mrestrepoj10@gmail.com>
- **Lines:** 342, 364, 365, 380, 386
- **Slug:** other-logic-bug
- **Confidence:** high
- **Revalidation:** confirmed
- **Reasoning:** Verified in `acquireAndMint`. The lock winner correctly honors the contract — the re-read at 342-345 is gated on `!request.forceRefresh`. The loser path is not: after `sleep(delay)` it calls `readToken(key)` at 364 and returns `fromWinner` whenever it is merely unexpired (365), with no check that this value was published after the forced refresh began and no `forceRefresh` guard at all. Nothing establishes provenance — there is no generation counter, and the token key's value is not sampled before waiting. The reachable scenario is precisely the one the code exists for: when a still-unexpired-but-provider-rejected token causes several concurrent 401 retries from `createApsClient` (which sets `forceRefresh: true`), the callers that lose the lock immediately receive that same rejected token. Note the in-process `inflight` coalescing at vault.ts:380-385 is also skipped for forced requests, so multiple forced callers in one process genuinely reach this loser path rather than sharing one promise. Since `requestJson` retries only once, those callers then fail outright, and any keep-alive or rotation job relying on `forceRefresh` silently performs no rotation while reporting success — a direct violation of the documented 'Skip caches and mint a fresh token' semantics in index.ts:27. Severity BUG is appropriate: it degrades availability and breaks a stated guarantee without directly disclosing credentials.

A caller that acquires the lock correctly skips the cache when forceRefresh is true. However, a concurrent forced caller that loses the lock polls the token key and returns any unexpired token already present, without establishing that it was written by the current lock holder. When a fresh-but-rejected token caused concurrent 401 retries, losing callers can immediately receive that same rejected token rather than the replacement. This violates the documented guarantee that forceRefresh skips every cache and can cause concurrent APS requests or keep-alive jobs to fail without performing the requested rotation.

**Recommendation:** Coalesce concurrent forced refreshes and return the resulting promise, or record a token generation/value before waiting and only accept a token proven to have been published after the forced refresh began. Do not return the pre-existing cache entry from the loser path.

---

