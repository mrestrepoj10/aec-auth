# aec-auth

**The token layer for AEC APIs.** Typed clients and pluggable OAuth token management for [Autodesk Platform Services](https://aps.autodesk.com) (APS) and [Procore](https://developers.procore.com) — built for Next.js, Nuxt, serverless, and agents.

> **Status: pre-alpha.** APIs will change. Not yet published to npm — that happens at launch.

## The problem

APS refresh tokens are **single-use**: every refresh invalidates the old token and returns a new one. In a serverless deployment, two concurrent invocations refreshing the same grant means one of them uses a dead token — and your user's connection is bricked until they re-consent. Most AEC integrations hit this in production and never find out why.

`aec-auth` exists to own that problem: token acquisition, caching, and **single-flight refresh** (in-process *and* cross-process) behind one small contract, so your route handlers never touch OAuth.

```ts
import { connectTokenSource } from 'aec-auth/connect'
import { createApsClient } from 'aec-auth/aps'

const tokens = connectTokenSource({ connectors: { aps: 'oauth/autodesk' } })

export async function GET() {
  const aps = createApsClient({ tokens, subject: { type: 'app' } })
  const hubs = await aps.hubs.list()
  return Response.json(hubs)
}
```

## Design

One interface down, two providers out. Everything implements or consumes `TokenSource`:

```
your app / agent / AI SDK tool
        │  aps.hubs.list() — header injected, 401 retried once
        ▼
  typed clients        aec-auth/aps · aec-auth/procore
        │  getToken({ provider, subject, scopes })
        ▼
  TokenSource backends
    ├─ aec-auth/connect      Vercel Connect (zero-config; tokens cached — Connect bills per request)
    ├─ aec-auth/authjs       Auth.js provider configs
    ├─ aec-auth/betterauth   Better Auth genericOAuth configs
    └─ aec-auth/vault        self-hosted (bring a store) — single-flight refresh lock
        │  OAuth 2.0: code + PKCE / client-credentials
        ▼
  Autodesk APS · Procore
```

- **Zero runtime dependencies.** Plain `fetch`, WinterCG-compatible — Node, edge, workers, Bun.
- **Backends are pluggable.** Vercel Connect is the zero-config default; the vault runs anywhere on any store that can do get/set/lock (Redis, Postgres, Upstash). `@vercel/connect`, `better-auth`, and `@auth/core` are optional peers, loaded lazily or type-only.
- **`aec-auth/mock`** gives you fake APS/Procore providers with realistic fixtures — try the clients, run CI, and demo with **zero credentials**.

## Entry points

| Import | What it is |
| --- | --- |
| `aec-auth` | The contract: `TokenSource`, `TokenError`, `withTokenCache`, endpoint constants, scope recipes |
| `aec-auth/aps` | Typed APS client (hubs, projects, generic `request`) + `apsAuthenticationProvider` for the official `@aps_sdk` clients |
| `aec-auth/procore` | Typed Procore client (companies, projects, `me`, generic `request`) |
| `aec-auth/connect` | Vercel Connect backend |
| `aec-auth/vault` | Self-hosted backend: `VaultStore` contract, `memoryVaultStore`, `encryptedVaultStore`, `apsOAuth`, `procoreOAuth` |
| `aec-auth/vault/upstash` | Production `VaultStore` over Upstash Redis (REST, edge-ready; optional peer `@upstash/redis`) |
| `aec-auth/authjs` | Auth.js provider configs for APS + Procore |
| `aec-auth/betterauth` | Better Auth `genericOAuth` configs for APS + Procore |
| `aec-auth/mock` | Mock token source + fixture-serving fetch for both providers |

## Using with the official APS SDK (`@aps_sdk/*`)

aec-auth does not replace Autodesk's official SDK — it sits underneath it. The division of labor:

- **aec-auth** owns the token lifecycle: minting, caching, storage, encryption, and rotation-safe refresh — the part `@aps_sdk` explicitly leaves to you.
- **`@aps_sdk`** (Model Derivative, Data Management, OSS, …) owns deep API coverage, maintained by Autodesk.
- **`aec-auth/aps`'s own client** stays useful where the official SDK doesn't run or is overkill: edge runtimes and workers (it is fetch-only, zero-dependency) and simple read paths.

The official clients accept an `authenticationProvider`; aec-auth ships a structural adapter for it, so the wiring is one line and this package takes no dependency on the SDK:

```ts
import { ModelDerivativeClient } from '@aps_sdk/model-derivative'
import { apsAuthenticationProvider } from 'aec-auth/aps'
import { tokens } from '@/lib/aps' // your TokenSource — vault, Connect, any backend

const md = new ModelDerivativeClient({
  authenticationProvider: apsAuthenticationProvider(tokens, { subject: { type: 'app' } }),
})

const manifest = await md.getManifest(urn) // token acquired, cached, refreshed by aec-auth
```

Scopes requested by the SDK per call win; otherwise the adapter's configured `scopes` (default `data:read`) apply. Works identically with a 3-legged subject (`{ type: 'user', id }`).

> **One rule when composing the two:** the vault must be the *only* owner of refresh for the grants it manages. Never call `@aps_sdk/authentication`'s `getRefreshToken()` yourself for a user the vault holds — APS refresh tokens are single-use, so an out-of-band refresh consumes the rotation behind the vault's back and kills the grant. Sign-in and consent can live anywhere; refresh lives in exactly one place.

## Production storage, locking, and encryption

The vault's persistence contract is deliberately tiny — `get`/`set`/`delete` plus an ownership-aware lock:

```ts
const lease = await store.acquireLock(key, ttlMs) // opaque lease, or null if held
await store.releaseLock(key, lease)               // compare-and-delete: only the owner releases
```

The lease is what makes the lock safe under real-world timing: a holder that stalls past its TTL cannot delete the lock a later process acquired. Both shipped stores implement it (Redis semantics: `SET key lease NX PX ttl` to acquire, a `GET`/`DEL` Lua script to release).

The production setup is two composed lines:

```ts
import { encryptedVaultStore, vaultTokenSource, apsOAuth } from 'aec-auth/vault'
import { upstashVaultStore } from 'aec-auth/vault/upstash'

const store = encryptedVaultStore(upstashVaultStore(), { key: process.env.VAULT_KEY! })
```

- `upstashVaultStore()` reads `UPSTASH_REDIS_REST_URL` / `UPSTASH_REDIS_REST_TOKEN` (or takes `url`/`token`, or a `Redis` instance created with `automaticDeserialization: false`). REST-based, so it runs on Node, edge, and workers alike.
- `encryptedVaultStore` is AES-256-GCM over WebCrypto: grants (refresh tokens) and cached access tokens are ciphertext at rest (`enc.v1:` values); lock leases pass through. `VAULT_KEY` is 32 bytes, base64 or hex — `openssl rand -base64 32`. A wrong key fails loudly; it never falls back to plaintext. **Without this wrapper, refresh tokens sit in your store as readable JSON** — use it (or storage-layer encryption) in production.
- The in-memory store remains the dev/test default; any other backend (Postgres, Cloudflare KV) is a small `VaultStore` implementation away, and `test/vault-stores.test.ts` shows the contract a new store must satisfy — including the stale-lease scenario.

## Development

```sh
pnpm install
pnpm build
pnpm test
```

### Trying it in a Next.js app — the playground

`apps/playground` is a minimal Next.js app whose home page runs every backend server-side on each request and renders a pass/skip/fail matrix — the fastest way to see all backends working in a real app context:

```sh
npx emulate --service aps                     # optional: emulator row passes too
APS_EMULATOR_URL=http://localhost:4000 pnpm --filter playground dev
# open http://localhost:3000 — JSON at /api/token
```

Rows unlock as env is provided: `APS_CLIENT_ID`/`APS_CLIENT_SECRET` (real 2-legged + live API call), `APS_CONNECTOR` (Vercel Connect). For someone starting fresh: `npx create-next-app`, add `aec-auth` (npm at launch; until then clone this repo and `pnpm add file:../aec-auth/packages/aec-auth` after `pnpm build`), and copy `apps/playground/lib/checks.ts` + the route handler as the starting point. A shadcn-style `init` scaffolder is on the roadmap.

### Deterministic integration tests — the APS emulator

[`@emulators/aps`](https://github.com/vercel-labs/emulate/pull/201) is a stateful emulator of the real APS OAuth v2 API, including single-use refresh rotation with grant-family invalidation. It gives the vault backend a real rotating OAuth server to test against — no credentials, no network:

```sh
npx emulate --service aps        # port 4000 (from the fork until the PR is released)
APS_EMULATOR_URL=http://localhost:4000 pnpm vitest run test/aps.emulator.test.ts
```

The suite drives the full 3-legged flow headlessly (consent page, code exchange, rotation ×2) and proves the failure mode this package exists to prevent: replaying a consumed refresh token invalidates the grant family.

With [portless](https://github.com/vercel-labs/portless), the emulator gets a stable HTTPS URL (`npx emulate start --portless` → `APS_EMULATOR_URL=https://aps.emulate.localhost`), and the 3-legged example accepts a stable callback you register once in your APS app: `CALLBACK_URL=https://aec-auth.localhost/callback portless aec-auth node examples/aps-3legged.mjs`. Both example scripts also take `APS_BASE_URL` to run against the emulator instead of real APS.

Monorepo: `packages/aec-auth` is the library; example apps land in `apps/` later.

## Roadmap

- [x] `TokenSource` contract, token cache, scope recipes
- [x] Vault backend with cross-process single-flight refresh
- [x] Vercel Connect, Auth.js, Better Auth backends
- [x] Typed APS + Procore clients, mock providers
- [x] Deterministic emulator tests (`@emulators/aps` — upstream PR to vercel-labs/emulate)
- [x] Official `@aps_sdk` interop — `apsAuthenticationProvider` adapter, live-tested (replaces the earlier plan to generate full API coverage ourselves)
- [ ] `aec-auth/acc` — typed client for the ACC modules Autodesk ships no SDK for (RFIs, Submittals, Sheets first; Issues and Account Admin already work via the `@aps_sdk` adapter). Rule of thumb: adapter where an official client exists, client where the surface is vacant
- [ ] Typed Procore client expansion (RFIs, submittals — no official Procore JS SDK exists)
- [ ] Webhook signature verification + typed payloads
- [ ] `init` / `doctor` CLI, Next.js template
- [ ] npm publish

## License

MIT © [Frame Labs](https://github.com/mrestrepoj10)
