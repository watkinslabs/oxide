# 12 Slab

DRAFT 2026-05-02. Dep:`01`,`02`,`06`,`08`,`09`,`10`. Provides:`kalloc` (GlobalAlloc), every kernel crate.

Small (≤8KiB) kernel objs; low frag, low contention, detectable corruption. Backed by PMM page alloc.

## 1 Frozen invariants

1. Alignment: returned ptr aligned to `max(min(size,64), requested_align)`.
2. No double-free: wrong-cache or repeat-free detected via cookie/redzone, panic.
3. No UAF (build window): freed objs `0xDD`-filled (debug); poison cookie at offset 0.
4. Cache correctness: returned to origin cache (cache_id stored in slab page metadata).
5. Per-CPU magazine ↔ global cache total-object-count consistency.

## 2 Public ifc

```rust
pub struct Cache<T> { /* private */ }
impl<T> Cache<T> {
  pub fn new(name:&'static str) -> Self;
  pub fn alloc(&self) -> KR<NonNull<T>>;             // # C: O(1) amortized
  pub fn free(&self, p:NonNull<T>);                   // # C: O(1) amortized
}

// kalloc GlobalAlloc fixed size-class caches:
pub fn kmalloc(size:usize, align:usize) -> KR<NonNull<u8>>;
pub fn kfree(p:NonNull<u8>, size:usize, align:usize);
```

Size classes: 8,16,32,64,96,128,192,256,384,512,768,1024,1536,2048,3072,4096,6144,8192. Larger → `pmm.alloc(order)` directly.

## 3 Design

### 3.1 Slab page
4KiB or 32KiB (`order_for_size`):
```
[ obj0 obj1 ... | redzone | freelist | cache_id | refcount ]
```
Per-page freelist via *offset* (not pointer) to catch bad writes.

### 3.2 Per-CPU magazine
```rust
struct Magazine { objs:[Option<NonNull<T>>;32], len:u8 }
```
alloc=pop local; free=push local. Empty/full ⇒ exchange w/ global under cache spinlock. ~32× contention reduction steady-state.

### 3.3 Global cache
```rust
struct CacheGlobal<T> {
  partial: Vec<&Slab<T>>,   # ≥1 free obj
  full:    Vec<&Slab<T>>,   # all objs free; return to PMM past watermark
  empty:   Vec<&Slab<T>>,   # cached few for refill
  lock:    Spinlock<()>,
}
```
Lock class `Slab` (> `Buddy`, < most others).

### 3.4 Hardening
- Redzone: 8B start+end magic; on `dev`/`debug-build`, off `release`.
- Freed-fill: `0xDD` over body on free.
- Poison cookie: 8B at offset 0 of every freed obj (separate from redzone); checked on alloc.
- Caller-PC tracking (`debug-alloc` only): per-obj ring of last 4 alloc/free PCs; dumped on UAF detect.

## 4 Concurrency

Per-CPU magazine: preempt-disable (no lock; `06§4`). Global exchange: `Slab` class spinlock `irqsave` (reachable from softirq). No nested cache calls.

## 5 Perf budget

| Op | p99 cy |
|---|---|
| `kmalloc(64)` magazine hit | 40 |
| `kfree(64)` magazine hit | 40 |
| `kmalloc(64)` mag-miss + global-hit | 200 |
| `kmalloc(64)` cold (PMM call) | 800 |

Hot-path round trip ≤ 80 cy per `04§1`.

## 6 Test contract (frozen)

- Oracle: `tools/oracle-slab/` `BTreeMap<usize,Vec<*mut u8>>` reference; proptest 1M ops/seed.
- Loom: 4 threads × 100 ops; alloc/free interleavings; no UAF/leak; depth 6.
- Miri: hosted unit tests; no UB.
- Stress: 100 threads × 1M alloc/free random sizes; redzone+poison check at end; zero corruption.
- Soak (bg, not gate per `40§3`): 4h SMP cycles, kernel-build+iperf3+fs_mark; objects-alive end ≈ start (slop). PR-time gate uses `paranoid-ci` (`debug-alloc`+redzone+poison per op).
- Coverage ≥95%.

## 7 Failure modes

- Redzone/poison mismatch on free: panic + obj dump.
- Free to wrong cache: panic + both cache_ids.
- Magazine len out of range: panic.
- OOM: `ENOMEM`; OOM killer upstream.

## 8 Debug

`debug-alloc`: redzone + freed-fill + poison + caller-PC + audit per op.

## 9 Log

`target="slab"`. error=corruption; warn=cache exhaustion; info=cache create.

## 10 Cross-spec

`10` (PMM backing), `kalloc` (GlobalAlloc impl uses size-class caches), every kernel crate consumes via `Box`/`Vec`/etc.

## 11 Changelog

(none)

## 12 OQ

- Magazine size 32: tune via bench.
- Per-NUMA caches: v2 (single-NUMA v1).
- Slab merging (multi types same size+align): defer; complicates type-tracking.
