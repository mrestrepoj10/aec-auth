---
'aec-auth': minor
---

Harden token cache identity, forced-refresh single-flight, renewable vault leases, grant deletion, and stale-token fencing.

Custom `VaultStore` implementations must add atomic `renewLock` and `compareAndSet` methods. The bundled memory, encrypted, and Upstash stores implement the expanded contract.
