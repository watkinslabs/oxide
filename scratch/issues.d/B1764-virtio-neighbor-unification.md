# B1764 — virtio neighbour ownership reconciliation

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| FIXED B1764 | INFRA | low | B1752's already-fixed driver neighbour-cache row remained open after B1754 unified both families, leaving the ledger to claim a split source of truth that no longer exists. | `a80571e94` is an ancestor of `origin/main`; the driver has no learned-neighbour state or solicitation path, while `net::neigh::resolve_or_queue` owns queued resolution. The archive now preserves the retired row with its fixing SHA. | B1764 |
