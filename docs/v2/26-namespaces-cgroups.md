# 26 Namespaces + cgroup v2 — v2 deferred entries

Carried at freeze 2026-05-02.

## Hierarchical CFS group scheduling

Per-cgroup runqueues. v1 = per-cgroup quota + weight at task pick time, not full hierarchy. Deferred.

## Cgroup BPF programs

v1.x with BPF.

## `cgroup.threads` vs `cgroup.procs` in unprivileged subtrees

Copy Linux delegation semantics exactly.

## `misc` controller

v1.x.
