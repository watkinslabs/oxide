# 10 PMM

FROZEN 2026-08-17. Dep:`01`,`02`,`04`,`06`,`08`,`09`. Provides:`11`,`12`,DMA drivers.

Buddy allocator owning all physical frames. Global buddy bitmaps are the source
of truth for mergeable free blocks; a distinct per-CPU bitmap is the source of
truth for cached order-0 pages. Every list is derived from its matching bitmap.
Disagreement ⇒ panic.

## 1 Purpose

Alloc/free phys frames orders 0..=`MAX_ORDER`=20 (4KiB..4GiB). Ordered DMA, DMA32, Normal, and Movable zone slots; architecture defaults leave Movable empty until an allocation class can use it. UMA only; NUMA remains phase 41. Doesn't know about VM or caches.

## 2 Inputs/outputs

- Deps: `01` (`PhysAddr`,`Pfn`,`Order`), `06` (Spinlock).
- Provides: `11`,`12`, DMA drivers.
- HW: none direct; reads firmware mem map at boot.

## 3 Frozen invariants

Hold at every quiescent point.

1. Bitmap-truth: ∀ order o, block-aligned PFN p: `buddy_bitmap[o].is_set(p)` ⇔ "block of order o starting at p is on a mergeable buddy list". `pcp_bitmap[p]` ⇔ "the order-0 page is free on exactly one per-CPU pageset".
2. Single-membership: a free block is either one global buddy block or one pageset page, never both. A global order-o block sets `buddy_bitmap[o]` only at its base; buddy bits at other orders covering that memory clear.
3. List ↔ bitmap: every global block on `free_list[o]` has its buddy bit set and vice versa; every pageset node has its `pcp_bitmap` bit set and vice versa.
4. Buddy alignment: order-o block at PFN p has p aligned to `1<<o`.
5. No overlap: no two global blocks, pageset pages, or a mixture of the two cover the same memory.
6. Total accounting: `sum_o (count(buddy_bitmap[o]) << o) + count(pcp_bitmap) + allocated == initial_free`.
7. Poison-on-free: freed page first 16B = `0xDEADBEEFCAFEBABE` + order(u8) + 7B zero. Verified on alloc.
8. `MAX_ORDER` bound: order > MAX_ORDER ⇒ `Err(ENOMEM)`.
9. Zone partition: every PFN below `pfn_max` belongs to exactly one ordered zone; a free block never straddles a zone boundary.
10. Zone bound: a GFP zone selector may allocate from that zone or a lower one, never a higher one. `alloc_below` rechecks the returned span and narrows the selector before retrying.
11. Zone gate: every allocation path checks its selected zone's watermark and low-memory reserve before taking a block; exhaustion enters the common reclaim/OOM slowpath.
12. Pageset shape: only order-0 pages enter a pageset. A free above its high mark detaches a batch before it takes the global buddy lock; an order-0 refill and every higher-order global miss return cached pages through the ordinary coalescer before retrying.

## 4 Public ifc

```rust
pub struct Pmm { /* private */ }

impl Pmm {
  pub fn init(regions:&[(Pfn,usize)]) -> Self;       // # C: O(n+N)
  pub fn reserve_early(&mut self, start:Pfn, len:usize);  // # C: O(len)
  pub fn alloc(&self, order:Order) -> KR<Pfn>;       // # C: O(MAX_ORDER); # Ctx: any; brief IRQ-off
  pub fn alloc_gfp(&self, order:Order, gfp:u32) -> KR<Pfn>; // # C: O(NR_ZONES×MAX_ORDER)
  pub fn alloc_below(&self, order:Order, limit:Pfn) -> KR<Pfn>; // # C: O(3×NR_ZONES×MAX_ORDER)
  pub fn free(&self, pfn:Pfn, order:Order);          // # C: O(MAX_ORDER); # Ctx: any
  pub fn free_pages(&self) -> u64;                    // # C: O(MAX_ORDER)
  pub fn allocated_pages(&self) -> u64;               // # C: O(1)
  pub fn free_orders(&self) -> [u64; ORDERS];         // # C: O(MAX_ORDER); per-order free-block snapshot under the buddy lock; backs `/proc/buddyinfo` (`19`)
  pub fn zone_snapshot(&self) -> [ZoneStat; NR_ZONES]; // # C: O(NR_ZONES×ORDERS); backs `/proc/zoneinfo` (`19`)
  pub fn audit(&self);                                // # C: O(N); quiescent debug check
}
```

## 5 Data structures

### 5.1 Bitmaps
One global-buddy bitmap per order: `buddy_bitmap[o]` bit i represents the
mergeable order-o block at PFN `i<<o`. The separate `pcp_bitmap` has one bit
per PFN and represents an order-0 page cached on one CPU. Total is still about
2N bits plus N bits. The slices are `[AtomicU64]` because the pageset path
observes ownership without taking the global lock.

### 5.2 Free lists
`free_list[zone][o]` = intrusive doubly-linked LIFO; node lives in freed page first 16+16B:
```rust
#[repr(C)]
struct FreeNode { poison:u64, order:u8, _pad:[u8;7], next:PfnOrNull, prev:PfnOrNull }
```
LIFO maximizes cache locality. Never deref free pages outside PMM.

### 5.3 Locks
`PmmInner` has one IRQ-safe global buddy lock. Each `(CPU, zone)` pageset has
its own IRQ-safe lock. Both are leaf locks and are never nested: a refill takes
and releases the buddy lock before publishing a batch to a pageset; a drain
detaches its pageset batch before taking the buddy lock to coalesce it.

### 5.4 Inner
```rust
struct PmmInner {
  bitmap:    [AtomicU64Slice; MAX_ORDER+1], // global mergeable blocks only
  layout:    ZoneLayout,
  zonelist:  Zonelist,
  free_list: [[PfnOrNull; MAX_ORDER+1]; NR_ZONES],
  free_count:[[u64;       MAX_ORDER+1]; NR_ZONES],
  managed:   [u64; NR_ZONES],
  present:   [u64; NR_ZONES],
  spanned:   [u64; NR_ZONES],
  reserve:   [[u64; NR_ZONES]; NR_ZONES],
  wmark:     [ZoneWatermarks; NR_ZONES],
  pfn_min: Pfn, pfn_max: Pfn,
  poisoning: bool,
}
```

### 5.5 Pagesets
`PcpSet` owns one intrusive LIFO `PcpList` for each logical CPU and populated
zone. A list node uses the same `FreeNode` header as a global order-0 block,
but its PFN is recorded in `pcp_bitmap`, never in `PmmInner.bitmap[0]`. Each
zone publishes atomically maintained total-free and cached-free page counts,
plus its watermark/reserve inputs, batch size and dynamic high mark. The batch
is bounded by the zone's managed pages; the high mark is the zone low watermark
divided by the live online CPU count, never less than four batches.

## 6 Algorithms

### 6.1 alloc(o)
```
if o == 0:
  for zone in zonelist at or below gfp_zone(gfp):
    if !watermark_ok(total_zone_free, reserve, mark): continue
    pop current_cpu.pageset[zone], if non-empty
    otherwise take up to batch order-0 pages from global buddy, publish all
      but the returned page to current_cpu.pageset[zone]
  zero returned page; return Ok(pfn)

lock global buddy;
for zone in zonelist at or below gfp_zone(gfp):
  if !watermark_ok(zone, o, reserve, mark): continue
  for k in o..=MAX_ORDER:
    if free_list[zone][k] non-empty:
      pop head -> pfn; clear bitmap[k][pfn]; free_count[zone][k] -= 1
      while k > o:
        k -= 1
        buddy = pfn + (1<<k); push (zone,buddy,k); set bitmap[k][buddy]; free_count[zone][k] += 1
      verify_poison(pfn, 1<<o)      # inside lock
      unlock; zero(pfn, 1<<o); return Ok(pfn)
unlock global buddy;
if a global miss has not drained eligible pagesets yet:
  detach every eligible pageset and return its pages through the coalescer
  retry once
return Err(ENOMEM)
```

Always lower half on a global split (deterministic). A pageset refill verifies
its global free-node poison before reusing that header as a pageset link. All
allocation paths zero outside their lock domain.

`alloc_below` resolves the address bound to a zone selector, calls this path, verifies the returned span, and returns an out-of-bound block before retrying one zone lower. It never scans a second address-indexed free-list path.

### 6.2 free(p,o)
```
if o == 0:
  set pcp_bitmap[p]; push p on current_cpu.pageset[zone]
  if pageset.count > pageset.high: detach one batch
  return a detached batch through the global coalescer

write_poison(p, o)               # before lock; page is ours
lock.lock_irqsave();
pfn,order = p,o
loop:
  buddy = pfn ^ (1<<order)        # XOR-buddy O(1)
  if order == MAX_ORDER: break
  if zone_of(buddy) != zone_of(pfn): break
  if !bitmap[order].is_set(buddy): break    # buddy allocated
  if !buddy_in_free_list(order,buddy): kassert!(false,"inv 3 violated")
  remove buddy from free_list[order]; clear bitmap[order][buddy]; free_count[order] -= 1
  pfn = min(pfn,buddy); order += 1
push (pfn,order); set bitmap[order][pfn]; free_count[order] += 1
unlock
```

Higher-order sibling existence is checked via the global buddy bitmap (O(1)
atomic), not a free-list walk. A pageset page is deliberately not a global
sibling until its drain transition, so a local cache cannot hide memory from a
higher-order allocation.

### 6.3 Boot
1. Parse firmware mem map (multiboot2/EFI/DTB) and derive the architecture's zone boundaries.
2. For each "usable" region: subtract reserved overlaps (kernel image, ACPI, fb), clip it to each zone, then push largest aligned blocks directly to that zone's free lists + bitmap.
3. Build the populated-zone fallback list and derive low-memory reserves and watermarks from the final per-zone managed counts.
4. Zero unpopulated bitmaps. Post-SMP: no more `reserve_early`; all alloc through the zone gate.

Boot path is sole exception to alloc/free symmetry; single audited fn.

## 7 Concurrency

Order-0 allocation first uses only the current CPU and the selected zone's
pageset lock. Its local fast path performs no global buddy-list mutation.
Refill and free-side draining move bounded batches between the two domains
without nesting their locks. High-order allocation remains global, but after a
global miss it drains eligible pagesets and retries, so cached pages cannot
manufacture an out-of-memory or fragmentation result. Global per-order counts
remain the `/proc/buddyinfo` view; total zone free counts include pagesets for
watermark and `/proc/zoneinfo` accounting.

## 8 Perf budget

| Op | p99 cy | p999 cy |
|---|---|---|
| `alloc(0)` uncontended | 80 | 200 |
| `alloc(0)` 16-CPU stress | 250 | 800 |
| `free(0)` no merge | 70 | 200 |
| `free(0)` full merge to MAX_ORDER | 400 | 1000 |
| `alloc(9)` 2MiB hugepage | 200 | 600 |

Bench: `bench/pmm_bench.rs` vs hosted oracle; `bench-history/`.

## 9 Test contract (frozen)

- Hosted unit: `init` from synthetic zone layouts, audit clean. Alloc every order once, verify split/merge and no merge across a zone boundary. Alloc-all then free-all in random order, verify bitmaps == boot state.
- Pagesets: an order-0 free is reused locally; a free over the high mark drains exactly one batch; an order-3 request drains cached constituent pages and coalesces them; a second free while cached panics on `pcp_bitmap`.
- Zone tests: every PFN maps to one zone; GFP fallback never rises above its bound; a DMA-bound allocation takes the watermark/reclaim path and retries below an unaddressable result.
- Property/oracle: `tools/oracle-buddy/` (sorted free list, no bitmap, recompute every op). proptest 1M ops `{alloc(rand_order),free(rand_outstanding)}`; per-op assert agreement on outstanding-PFN-set, per-order free count, total free.
- Loom: 4 threads × 100 ops `{alloc(0),free(rand)}`; depth 6; no deadlock/double-count/UAF/leak. BTreeMap-based pre-alloc tracker stands in for bitmap (loom can't model multi-MiB atomics; logic-only).
- Miri: hosted unit tests; no UB, no leak.
- PR-time gate uses `paranoid-ci` build (`debug-pmm` + `debug-alloc` audit per op) per `41§3`. Randomized 8-worker concurrent alloc/free with poison-corruption + double-free injection runs in proptest harness; kassert fires on detection.
- Coverage: ≥97% lines `crates/pmm/src/`. Every `unsafe` SAFETY ≥30ch.
- Bench regress: PR vs `bench-history/main`; >5% any op = fail.

## 10 Failure modes

- audit invariant violation: kernel panic; no recovery (PMM corruption ⇒ everything corrupted).
- Poison mismatch on alloc: panic; dump PFN, expected, actual, (debug-pmm: last 8 events for this PFN).
- OOM: `Err(ENOMEM)`; OOM killer (`27`) decides upstream.
- `free` mismatched order: kassert (caller bug).
- `free` PFN outside `[pfn_min,pfn_max]`: kassert.

## 11 Debug

- `debug-pmm`: audit() per op (≥10× slow); free-list↔bitmap consistency per op; full-page poison check; per-PFN ring of last 8 alloc/free events.
- `debug-pmm-track-leaks`: caller-PC per alloc; shutdown dumps unfreed PFNs + PCs.

## 12 Log

`target="pmm"`. error=invariant violation; warn=high-watermark (≤10% free); info=boot summary; debug=per op (debug-pmm only); trace=unused (too expensive).

## 13 Cross-spec

`11`,`12` (consumers). DMA drivers (`35`). Memory hotplug tracked as later phase; revising invariants 1,4,6 needed.

## 14 Changelog

(none)
