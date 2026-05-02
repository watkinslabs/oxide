# 11 VMM — v2 deferred entries

Carried from `docs/11-vmm.md` at freeze 2026-05-02.

## VMA merge timing

v1 lean = eager (merge on every successful adjacency). v2 considers lazy if eager merge cost shows in profiles.

## Per-VMA locks

Linux 6.4+ pattern. Deferred to v1.x.

## THP via `MADV_HUGEPAGE`

v1 lean = yes; kernel allocates 2 MiB on first fault when VMA is aligned + marked.

## userfaultfd

v1 lean = yes (Go runtime, CRIU).

## `MAP_HUGETLB` (reserved hugepages, no THP)

Deferred to v1.x.
