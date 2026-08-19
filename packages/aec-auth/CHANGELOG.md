# aec-auth

## 0.3.0

Security hardening across the vault and token cache (DeepSec/Codex findings plus review fixes).

- `VaultStore` contract expanded — **breaking for custom stores**: atomic `renewLock` and `compareAndSet` are now required. The bundled memory, encrypted, and Upstash stores implement the expanded contract.
- Refresh critical sections hold a heartbeat-renewed lease; rotation and grant writes are fenced with compare-and-set. Lease loss can no longer publish stale state or resurrect a deleted grant, and the refresh-token replay window shrinks from the full lease TTL to the moments between provider rotation and persistence — a residual risk inherent to single-use tokens over distributed leases.
- Cached access tokens bind to grant generations: deleting a grant invalidates every token it minted.
- `requestKey` now emits an unambiguous structured encoding (delimiter-proof); previously cached tokens become cold misses.
- Forced refreshes single-flight correctly: same-key callers coalesce, and a forced caller never adopts a pending cache-served run — a `forceRefresh` always yields a real rotation.
- CI actions pinned to commit SHAs with read-only permissions.

## 0.2.0

Breaking scope change: the package supports the Autodesk path (APS / ACC) with Better Auth as the only auth-library integration.

- Removed the `aec-auth/authjs` entrypoint and the `@auth/core` optional peer — Better Auth (`aec-auth/betterauth`) is the supported auth-library integration
- Removed all Procore support: the `aec-auth/procore` entrypoint, `procoreOAuth`, `procoreGenericOAuth`, Procore mocks and endpoint constants; `Provider` narrows to `'aps'`
- Procore support returns in a future release (OAuth provider, Better Auth config, and a typed client)

## 0.1.1

- Ship the MIT license text in the tarball

## 0.1.0

First published release: the token layer for AEC APIs (Autodesk Platform Services, Procore).

- `TokenSource` contract with typed `TokenError` codes, expiry-aware caching, and in-process single-flight
- Vault backend: rotation-safe single-use refresh with cross-process lock leases, AES-256-GCM encryption at rest, Upstash Redis production store
- Vercel Connect, Auth.js, and Better Auth backends (emulator-ready via `baseUrl`)
- Typed APS and Procore clients (fetch-only, runtime-agnostic) with 401-retry
- `apsAuthenticationProvider` interop adapter for the official `@aps_sdk` clients
- Mock providers, and deterministic full-flow coverage via the `@emulators/aps` emulator
