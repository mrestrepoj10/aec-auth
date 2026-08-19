# aec-auth

## What this codebase does

`aec-auth` is a TypeScript library and monorepo for acquiring, caching, storing, and rotating Autodesk Platform Services (APS/ACC) OAuth tokens.
It exposes a runtime-neutral `TokenSource` contract consumed by a typed APS client and the official APS SDK adapter.
The self-hosted vault supports app-level client credentials and user-level authorization-code grants, including cross-process refresh locking.
Optional backends integrate with Vercel Connect, Better Auth, and Upstash Redis; AES-256-GCM storage encryption is available as a wrapper.

Important ingress families:

- Public library entry points accept token requests, OAuth configuration, subjects, scopes, storage implementations, URLs, and arbitrary APS request paths.
- The playground exposes an unauthenticated server-rendered page and `/api/token` diagnostics endpoint that can make real APS, emulator, or Vercel Connect requests.
- The documentation app publicly serves MDX pages and generated Open Graph image endpoints, including a slug-based route backed by an allowlist.
- Executable examples provide two-legged and three-legged command-line flows; the latter also starts a local OAuth callback HTTP server.
- No implemented RPC, webhook, queue, cron/job, or agent-tool ingress was found; these appear only in documentation or roadmap language.

## Auth shape

- `TokenSource.getToken` takes a provider, an app or user subject, scopes, and an optional `forceRefresh`; subject authorization is delegated to the consuming application.
- `apsOAuth` implements client credentials, authorization-code exchange, optional S256 PKCE, refresh, and consent URL construction for APS OAuth v2.
- `vaultTokenSource` caches access tokens and serializes refreshes with in-process promises plus ownership-aware store leases.
- `connectTokenSource` delegates subject-aware token acquisition to Vercel Connect, while `apsGenericOAuth` supplies Better Auth provider configuration.
- `createApsClient` injects bearer tokens and retries one 401 with a forced refresh; `encryptedVaultStore` protects persisted grants and access tokens at rest.

## Threat model

- Refresh tokens and cached bearer tokens are the primary secrets; theft permits user or application access to APS/ACC resources.
- APS refresh tokens are single-use, so duplicate refresh owners, expired leases, or out-of-band SDK refreshes can invalidate an entire grant family.
- Applications must bind `{ type: 'user', id }` to an authenticated and authorized session before calling the library or accessing stored grants.
- Configurable OAuth/API base URLs, redirect URIs, scopes, and generic client request paths cross trust boundaries and must not be derived from untrusted requests.
- Public diagnostics or callback routes can trigger paid/provider operations, disclose operational metadata, or enable refresh churn if deployed without surrounding controls.

## Project-specific patterns to flag

- `createApsClient.request` accepts an arbitrary path and `RequestInit`; review callers for scope escalation, unsafe methods, and user-controlled path/query material.
- `apsOAuth` and Better Auth accept configurable `baseUrl` values; production callers should use fixed allowlisted origins and HTTPS.
- The vault's 10-second lease is not renewed; a token endpoint call exceeding the lease can allow a second process to enter the single-use refresh path.
- Concurrent or attacker-triggered `forceRefresh` calls bypass normal cache reuse and may repeatedly rotate a user's grant or increase provider cost.
- The playground returns caught provider error messages and performs live checks on every unauthenticated request; treat it as development-only or protect it.

## Known false-positives

- `mockTokenSource`, `mockApsFetch`, deterministic mock bearer strings, and fixture identifiers are intentional zero-credential development helpers.
- `aps-test-client`, `aps-test-secret`, localhost callback URLs, and emulator origins in playground/example code are documented emulator defaults, not repository secrets.
- HTTP Basic authentication in `apsOAuth` is the APS confidential-client token-endpoint mechanism; the fixed production endpoint is HTTPS.
- AES-GCM uses a fresh random IV and binds the store key as additional authenticated data; unencrypted lock leases are random ownership tokens by design.
- `memoryVaultStore` keeps plaintext values and process-local locks intentionally for development; production guidance composes Upstash with `encryptedVaultStore`.
