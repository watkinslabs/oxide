# 17 Block + Pagecache — v2 deferred entries

Carried at freeze 2026-05-02.

## `O_DIRECT`

Bypass page cache; requires user pages pinned + aligned. v1 lean = yes (database workloads need).

## Encrypted pagecache (fscrypt)

v2.

## `ioprio` per-process I/O weight

v1 = simple weight at submit. Aggressive scheduling (Linux mq-deadline-equivalent) deferred to v1.x.

## `kflushd` worker count

v1 lean = one per device (predictable per-device backpressure). v2 considers shared pool.
