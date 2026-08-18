---
"aec-auth": minor
---

Breaking scope reduction (pre-1.0): the package now supports the Autodesk Platform Services / ACC path only.

- Removed the Auth.js entrypoint (`aec-auth/authjs`). Better Auth (`aec-auth/betterauth`) is the supported auth-library integration; the `@auth/core` peer dependency is gone.
- Removed Procore support: the `aec-auth/procore` client, `procoreOAuth`, `procoreGenericOAuth`, `mockProcoreFetch`, `procoreFixtures`, and the `PROCORE_*` endpoint constants. The `Provider` type narrows to `'aps'`. Procore returns in a future release.
