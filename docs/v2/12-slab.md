# 12 Slab — v2 deferred entries

Carried from `docs/12-slab.md` at freeze 2026-05-02.

## Magazine size

v1 = 32 (initial guess); tune via benchmark.

## Per-NUMA caches

v1 = single NUMA only. v2 adds per-NUMA cache layer.

## Slab merging across types

Same-size + same-align types share underlying slabs (Linux `SLAB_MERGE`). Complicates type tracking; deferred.
