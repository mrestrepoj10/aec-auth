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
| `aec-auth/aps` | Typed APS client (hubs, projects, generic `request`) |
| `aec-auth/procore` | Typed Procore client (companies, projects, `me`, generic `request`) |
| `aec-auth/connect` | Vercel Connect backend |
| `aec-auth/vault` | Self-hosted backend: `VaultStore` contract, `memoryVaultStore`, `apsOAuth`, `procoreOAuth` |
| `aec-auth/authjs` | Auth.js provider configs for APS + Procore |
| `aec-auth/betterauth` | Better Auth `genericOAuth` configs for APS + Procore |
| `aec-auth/mock` | Mock token source + fixture-serving fetch for both providers |

## Development

```sh
pnpm install
pnpm build
pnpm test
```

Monorepo: `packages/aec-auth` is the library; example apps land in `apps/` later.

## Roadmap

- [x] `TokenSource` contract, token cache, scope recipes
- [x] Vault backend with cross-process single-flight refresh
- [x] Vercel Connect, Auth.js, Better Auth backends
- [x] Typed APS + Procore clients, mock providers
- [ ] OpenAPI-generated client coverage (Model Derivative, ACC, Procore RFIs/submittals)
- [ ] Webhook signature verification + typed payloads
- [ ] `init` / `doctor` CLI, Next.js template
- [ ] npm publish

## License

MIT © [Frame Labs](https://github.com/mrestrepoj10)
