# aec-auth

**The token layer for Autodesk Platform Services.** A typed client and pluggable OAuth token management for [Autodesk Platform Services](https://aps.autodesk.com) (APS / ACC) — built for Next.js, Nuxt, serverless, and agents. More AEC providers (Procore next) are on the roadmap.

> **Status: 0.x.** Published to npm (`pnpm add aec-auth`); APIs may still change before 1.0.

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

Everything implements or consumes `TokenSource`:

```
your app / agent / AI SDK tool
        │  aps.hubs.list() — header injected, 401 retried once
        ▼
  typed client         aec-auth/aps
        │  getToken({ provider, subject, scopes })
        ▼
  TokenSource backends
    ├─ aec-auth/connect      Vercel Connect (zero-config; tokens cached — Connect bills per request)
    ├─ aec-auth/betterauth   Better Auth genericOAuth config
    └─ aec-auth/vault        self-hosted (bring a store) — single-flight refresh lock
        │  OAuth 2.0: code + PKCE / client-credentials / jwt-bearer (SSA)
        ▼
  Autodesk APS / ACC
```

- **Zero runtime dependencies.** Plain `fetch`, WinterCG-compatible — Node, edge, workers, Bun.
- **Backends are pluggable.** Vercel Connect is the zero-config default; the vault runs anywhere on any store that can do get/set/lock (Redis, Postgres, Upstash). `@vercel/connect` and `better-auth` are optional peers, loaded lazily or type-only.
- **`aec-auth/mock`** gives you a fake APS provider with realistic fixtures — try the client, run CI, and demo with **zero credentials**.

## Entry points

| Import | What it is |
| --- | --- |
| `aec-auth` | The contract: `TokenSource`, `TokenError`, `withTokenCache`, endpoint constants, scope recipes |
| `aec-auth/aps` | Typed APS client (hubs, projects, generic `request`) + `apsAuthenticationProvider` for the official `@aps_sdk` clients |
| `aec-auth/connect` | Vercel Connect backend |
| `aec-auth/vault` | Self-hosted backend: `VaultStore` contract, `memoryVaultStore`, `encryptedVaultStore`, `apsOAuth` |
| `aec-auth/vault/upstash` | Production `VaultStore` over Upstash Redis (REST, edge-ready; optional peer `@upstash/redis`) |
| `aec-auth/betterauth` | Better Auth `genericOAuth` config for APS |
| `aec-auth/mock` | Mock token source + fixture-serving APS fetch |
| `aec-auth/webhooks` | APS Webhooks: callback signature verification + hooks/secret-token client |
| `aec-auth/ssa` | Secure Service Account management: accounts and signing keys |

The typed client retries `429` responses automatically, honoring the `Retry-After` header (with capped, jittered backoff as the fallback), and `apsPaginate` drains any paged APS/ACC listing — Data Management `links.next`, ACC `pagination.nextUrl`/offset, and webhooks `pageState` envelopes — behind one async iterator:

```ts
import { apsPaginate, createApsClient } from 'aec-auth/aps'

const client = createApsClient({ tokens, subject: { type: 'app' } })
for await (const issue of apsPaginate(client, `/construction/issues/v1/projects/${p}/issues`)) {
  // every item from every page, fetched lazily
}
```

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

The vault's persistence contract is deliberately tiny — `get`/`set`/`delete`, compare-and-set, plus an ownership-aware renewable lock:

```ts
const lease = await store.acquireLock(key, ttlMs) // opaque lease, or null if held
await store.renewLock(key, lease, ttlMs)           // compare-and-extend while still owned
await store.releaseLock(key, lease)               // compare-and-delete: only the owner releases
await store.compareAndSet(key, before, after)      // fence grant rotation/deletion
```

The vault renews the lease throughout refresh and verifies ownership before publishing a token. Grant rotation and deletion also use compare-and-set, so a stale holder cannot recreate or overwrite a newer grant. Both shipped stores implement these operations atomically with Redis-style compare scripts.

The production setup is two composed lines:

```ts
import { encryptedVaultStore, vaultTokenSource, apsOAuth } from 'aec-auth/vault'
import { upstashVaultStore } from 'aec-auth/vault/upstash'

const store = encryptedVaultStore(upstashVaultStore(), { key: process.env.VAULT_KEY! })
```

- `upstashVaultStore()` reads `UPSTASH_REDIS_REST_URL` / `UPSTASH_REDIS_REST_TOKEN` (or takes `url`/`token`, or a `Redis` instance created with `automaticDeserialization: false`). REST-based, so it runs on Node, edge, and workers alike.
- `encryptedVaultStore` is AES-256-GCM over WebCrypto: grants (refresh tokens) and cached access tokens are ciphertext at rest (`enc.v1:` values); lock leases pass through. `VAULT_KEY` is 32 bytes, base64 or hex — `openssl rand -base64 32`. A wrong key fails loudly; it never falls back to plaintext. **Without this wrapper, refresh tokens sit in your store as readable JSON** — use it (or storage-layer encryption) in production.
- The in-memory store remains the dev/test default; any other backend (Postgres, Cloudflare KV) is a small `VaultStore` implementation away, and `test/vault-stores.test.ts` shows the contract a new store must satisfy — including the stale-lease scenario.

## Service accounts (SSA)

A [Secure Service Account](https://aps.autodesk.com/en/docs/ssa/v1/developers_guide/overview/) is a non-human identity owned by your APS app. It authenticates by signing a **JWT assertion** with an RSA private key and exchanging it for a **3-legged access token** that acts as the service account "user" — no authorization code, no consent screen, and **no refresh token**; a fresh token is minted whenever one is needed. That makes SSA the right subject for agents, schedulers, and background jobs that must act in ACC without a human's grant.

Wiring is the vault plus a key resolver:

```ts
import { apsOAuth, vaultTokenSource } from 'aec-auth/vault'

const tokens = vaultTokenSource({
  store,
  providers: {
    aps: apsOAuth({
      clientId: process.env.APS_CLIENT_ID!,
      clientSecret: process.env.APS_CLIENT_SECRET!, // confidential clients only
      serviceAccountKeys: async (id) =>
        id === process.env.APS_SSA_ID
          ? { keyId: process.env.APS_SSA_KEY_ID!, privateKey: process.env.APS_SSA_PRIVATE_KEY! }
          : null,
    }),
  },
})

const token = await tokens.getToken({
  provider: 'aps',
  subject: { type: 'service_account', id: process.env.APS_SSA_ID! },
  scopes: ['data:read'],
})
```

The vault caches SSA tokens, single-flights mints in-process, and serializes them across processes on the store lock — load-bearing here, because APS caps the jwt-bearer exchange at **10 requests/minute per app**. Accounts and keys are managed with `createSsaAdminClient` from `aec-auth/ssa` (2-legged, `apsScopes.ssaAdmin`); the `privateKey` PEM that `keys.create` returns is shown **exactly once** — persist it immediately (an `encryptedVaultStore`-backed secret works well). APS returns keys as PKCS#1 PEM (`BEGIN RSA PRIVATE KEY`); the signer accepts both that and PKCS#8, including `\n`-escaped strings pasted from JSON or env vars.

> **Admin provisioning prerequisite — or the token sees nothing.** An SSA token is useless until an ACC/BIM 360 admin: (1) adds the app's **Client ID as a custom integration**, (2) invites the **service account's email** (`<name>@<clientId>.adskserviceaccount.autodesk.com`) as a member, and (3) subscribes it to products and assigns project roles / folder permissions like any human member. "My SSA token returns empty hubs" is almost always this.

Documented limitations: BIM 360 **Admin API** (`/hq/v1/…`) calls don't accept 3-legged tokens, SSA included — keep using `{ type: 'app' }` there. **Fusion hubs** are not supported. **Design Automation** WorkItem management doesn't accept 3-legged tokens (SSA tokens still read/write the ACC data those jobs touch). Accounts idle for 12 months are auto-`DEACTIVATED`; re-enable via `accounts.setStatus`.

**Vercel Connect cannot mint SSA tokens** — its custom OAuth supports only authorization-code and client-credentials, and SSA needs a signed JWT assertion. `connectTokenSource` rejects `service_account` subjects with a typed `not_configured`; use the vault for SSA (both backends can coexist behind the same `TokenSource` consumer).

## Webhooks

`aec-auth/webhooks` turns polling into events: register hooks with `createWebhooksClient` (any `TokenSource`, any subject — SSA included) and verify callbacks with `verifyWebhookSignature`:

```ts
import { createWebhooksClient, verifyWebhookSignature } from 'aec-auth/webhooks'

const webhooks = createWebhooksClient({ tokens, subject: { type: 'app' } })
await webhooks.secretToken.set(process.env.APS_WEBHOOK_SECRET!)
const { hookId } = await webhooks.hooks.create({
  system: 'data',
  event: 'dm.version.added',
  callbackUrl: 'https://app.example.com/api/webhooks/aps',
  scope: { folder: 'urn:adsk.wipprod:fs.folder:co.abc' },
})

// In the callback route — verify the RAW body before JSON.parse:
export async function POST(request: Request) {
  const payload = await request.text()
  const ok = await verifyWebhookSignature({
    payload,
    signature: request.headers.get('x-adsk-signature'),
    secret: process.env.APS_WEBHOOK_SECRET!,
  })
  if (!ok) return new Response(null, { status: 401 })
  const event = JSON.parse(payload)
  // …
}
```

## Development

```sh
pnpm install
pnpm build
pnpm test
```

Documentation site: `apps/docs` (`pnpm --filter docs dev`).

### Trying it in a Next.js app — the playground

`apps/playground` is a minimal Next.js diagnostics app. Its public home page is passive; detailed checks are available only through a bearer-protected API and are coalesced/cached for one minute:

```sh
npx emulate --service aps # optional: emulator row passes too
PLAYGROUND_DIAGNOSTICS_TOKEN=local-secret \
  APS_EMULATOR_URL=http://localhost:4000 pnpm --filter playground dev
curl -H 'Authorization: Bearer local-secret' http://localhost:3000/api/token
```

Checks unlock as env is provided: `APS_CLIENT_ID`/`APS_CLIENT_SECRET` (real 2-legged + live API call), `APS_CONNECTOR` (Vercel Connect). Keep the diagnostics token in a secret manager and call the endpoint only from trusted administrative tooling; detailed results intentionally remain server-side otherwise.

### Deterministic integration tests — the APS emulator

[`@emulators/aps`](https://github.com/vercel-labs/emulate/pull/201) is a stateful emulator of the real APS OAuth v2 API, including single-use refresh rotation with grant-family invalidation. It gives the vault backend a real rotating OAuth server to test against — no credentials, no network:

```sh
npx emulate --service aps        # port 4000 (from the fork until the PR is released)
APS_EMULATOR_URL=http://localhost:4000 pnpm vitest run test/aps.emulator.test.ts
```

The suite drives the full 3-legged flow headlessly (consent page, code exchange, rotation ×2) and proves the failure mode this package exists to prevent: replaying a consumed refresh token invalidates the grant family.

The Better Auth config accepts the same `baseUrl` override, so full sign-in flows are testable the same way: `test/betterauth.emulator.test.ts` runs a complete headless Better Auth sign-in against the emulator's consent UI — through code exchange, user creation, and hand-off of the refresh token to the vault — with zero credentials. The hand-off is a custody *move*, not a copy: after `saveUserGrant`, clear the refresh token from the auth library's account storage, so nothing can replay it once the vault rotates (the single-refresh-owner rule, enforced rather than just documented).

With [portless](https://github.com/vercel-labs/portless), the emulator gets a stable HTTPS URL (`npx emulate start --portless` → `APS_EMULATOR_URL=https://aps.emulate.localhost`), and the 3-legged example accepts a stable callback you register once in your APS app: `CALLBACK_URL=https://aec-auth.localhost/callback portless aec-auth node examples/aps-3legged.mjs`. Both example scripts also take `APS_BASE_URL` to run against the emulator instead of real APS.

Monorepo: `packages/aec-auth` is the library; example apps land in `apps/` later.

## Roadmap

- [x] `TokenSource` contract, token cache, scope recipes
- [x] Vault backend with cross-process single-flight refresh
- [x] Vercel Connect and Better Auth backends
- [x] Typed APS client, mock provider
- [x] Deterministic emulator tests (`@emulators/aps` — upstream PR to vercel-labs/emulate)
- [x] Official `@aps_sdk` interop — `apsAuthenticationProvider` adapter, live-tested (replaces the earlier plan to generate full API coverage ourselves)
- [ ] `aec-auth/acc` — typed client for the ACC modules Autodesk ships no SDK for (RFIs, Submittals, Sheets first; Issues and Account Admin already work via the `@aps_sdk` adapter). Rule of thumb: adapter where an official client exists, client where the surface is vacant
- [ ] Procore support returns: OAuth provider, Better Auth config, and a typed client (RFIs, submittals — no official Procore JS SDK exists)
- [x] Secure Service Accounts: `service_account` subject (jwt-bearer via the vault) + `aec-auth/ssa` admin client
- [x] Webhook signature verification + hooks client (`aec-auth/webhooks`; typed per-event payloads still open)
- [x] 429/`Retry-After` retry in the typed client; `apsPaginate` for all three APS page envelopes
- [ ] `init` / `doctor` CLI, Next.js template
- [x] npm publish (`aec-auth@0.1.0`)

## License

MIT © [Frame Labs](https://github.com/mrestrepoj10)
