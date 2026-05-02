# 06 Memory Model — v2 deferred entries

Carried from `docs/06-memory-model.md` at freeze 2026-05-02 per `02§9.8`.

## Spinlock implementation

v1 lean = MCS (avoids ticket-spinlock thrashing >16 CPU). Choice between MCS and CLH revisited at first SMP scaling work; the MCS-vs-CLH tradeoff is not a v1 wall.

## RCU implementation

v1 lean = task-RCU (simple; longer grace periods). v2 considers tree-RCU (~6 KLOC, near-instant grace, much higher complexity) when measured grace-period latency becomes a phase-1+ blocker.

## Cacheline detection

v1 = compile-time const default 64; HAL override per arch. v2 considers runtime detection (Apple silicon = 128). Revisit when first-class Apple silicon support is in scope.

## DMA barriers (HAL vs per-driver asm)

v1 lean = HAL-level. Per-driver asm fallback only if a specific device exposes ordering requirements the HAL barrier set doesn't already cover. Revisit when first PCIe driver lands.

## `SeqCst` audit lint

Lint requiring `// SAFETY:`-style justification on every `SeqCst` use. Designed in; deferred to a `spec-lint code/seqcst` rule once kernel code exists. Tracked here so it isn't lost.
