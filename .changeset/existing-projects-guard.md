---
"aec-auth": patch
---

`upstashVaultStore` now fails loudly when its Redis client auto-deserializes values (create the vault's client with `automaticDeserialization: false`); silent re-serialization could break compare-and-set fencing. Docs gain an "existing projects" guide.
