# 10 PMM — v2 deferred entries

Carried from `docs/10-pmm.md` at freeze 2026-05-02.

## ZONE_DMA32 (32-bit DMA)

v1 drivers all 64-bit DMA. v1 lean = single zone; add only if a v1.x driver needs it.

## Per-CPU cache layer

~3× p99 cut on cross-CPU rebalance, at cross-CPU rebalance complexity cost. Deferred to v1.x.

## PFN metadata array

`struct page`-equivalent, ~1 cacheline × N pages ≈ 1.5% RAM. v1 = yes, allocated at boot sized by max PFN. Detailed layout spec'd in `11`. Listed here for completeness.

## Boot bitmap placement strategy

v1 lean = lowest-addr-that-fits (deterministic + debuggable). v2 may revisit if measured fragmentation justifies first-fit / best-fit.
