# aec-auth

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
