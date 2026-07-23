## Handoff: heap corruptor PROVEN = CPU stale-kernel-pointer UAF into static heap; IRQ deadlock fixed

### Headline
Two fixes merged this session + the corruptor definitively characterized:
- **B1344 (merged, PR#3836): IRQ-safety deadlock fixed** — moved `reap_orphans`+
  `tick_wake_expired`+`psi::tick` off the hard-IRQ tick into the ktimers kthread
  (they took REG/ZOMBIES/child_sigq/PSI plain locks + rq.inner from IF=0 →
  self-deadlock). Boots to same point, no regression. NOT the corruptor (a
  spinlock nested on one CPU hangs, can't torn-write).
- **C202 (merged, PR#3837): corruption-probe on the fast profile** — the tool that
  cracked the device-vs-CPU question.
- **B1343 (merged earlier) doc RETRACTED** (D360, this branch): the virtio used-ring
  theory was over-fitting one sample — DISPROVEN below.

### THE PROOF — corruptor is a CPU stale-KERNEL-pointer write into the static heap
Enabled `[KALLOC] corruption-probe` on `debug-dealloc-diag` (C202) and booted 3×.
Every corrupt free-list node is in the **static heap** (`ffffffff81xxxxxx` = the 64 MiB
`STATIC_HEAP` BSS) and probes as:
```
refcount=0 mapcount=0 not-pmm-managed (kernel-image/reserved frame, never seeded into the buddy)
```
Decisive elimination:
- **not-pmm-managed** ⇒ the frame is NEVER in the buddy → no device can be handed it
  (rules out device DMA / used-ring / reservation-overlap) and it's not a buddy double-alloc.
- **mapcount=0** ⇒ no userspace/foreign mapping reaches it (rules out the double-map /
  wild-cross-write hypothesis the probe was built for).
- **refcount=0** ⇒ nothing holds a struct-page ref.
⇒ **kernel code holds a `*mut` into a freed static-heap block and writes it after free.**
Value is incidental (boots show `size=0`, `0xaaaaaa`, `0x80ffb180ffffffff`, `2<<32`, …).
This matches the pre-session 3-agent conclusion (CPU UAF), now PROVEN.

### DISPROVED this session (don't re-chase)
- **virtio used-ring UAF (my own B1343 theory)**: byte-decode was one-sample over-fit;
  other boots aren't used-ring-shaped; a recycled ring frame lands in a GROWN HHDM
  region (`ffff8000…`), NOT the static heap.
- **`release_transport_record` frees an active ring**: traced with a `[VRING-FREE]`
  klog — **0 hits during boot**. The unpublish path is never taken. Not the free path.
- **`reset_device` quiescence**: SAFE (spins on status→0). Queue-alloc rollback: SAFE
  (frees before programming).
- **device DMA into an overlapping/freed frame; userspace double-map; buddy overlap**:
  all excluded by the refcount=0/mapcount=0/not-pmm-managed classification.

### Secondary anomaly seen (investigate, may be unrelated)
One probe hit a GROWN-region node (`ffff8000799e85f0`, HHDM) that IS buddy-MANAGED with
`refcount=1 mapcount=0 flags=0x18000 kheap=set`. A permanent-KHEAP grown frame carrying
`refcount=1` is unexpected (kalloc_grow stamps KHEAP and shouldn't leave a struct-page
ref). Worth checking `kalloc_grow`/`alloc_object_frame` for a stray inc_ref on a heap
frame — but the PRIMARY corruptor is the static-heap CPU-UAF above.

### First task next session — NAME THE WRITER
1. **Hardware watchpoint** (`debug-hw-watchpoint` already wired: `pmm::boot::watchpoint_arm`
   → DR0/DR1 on a just-freed HoleHdr → `#DB` prints the writer rip via hal-x86_64).
   Enable it: `qemu_start(features="debug-boot,debug-dealloc-diag,debug-hw-watchpoint")`,
   `qemu_continue`, grep serial for `[HWWP]`/rip. CAVEAT: it's v1 single-block and the
   write "propagates past quarantine" (the `0xEE` poison is never seen → the write lands
   on an OLD freed block, not the most-recently-freed watched one). So FIRST widen the
   watch to rotate/hold more blocks, OR watch the specific recurring victim slot
   (`ffffffff81b46e90`-class addresses recur run-to-run since the static heap layout is
   deterministic — pin a watch there early).
2. Then audit the kernel code whose `*mut`/raw pointer into a freed kalloc block could
   survive the free — the classic "cache a raw ptr into a Box/Vec, free it, write later"
   in an early-boot subsystem (the corruption fires by systemd early-service startup,
   clustered at the `[ZRAM-SYSFS] disksize=` alloc burst = detection point, not cause).

### Boot recipe
`qemu_start(x86_64, features="debug-boot,debug-dealloc-diag", paused=false)` → **then
`qemu_continue`** (REQUIRED — paused=false still leaves it stopped-under-gdb; it times
out at 120s, expected) → `qemu_serial` (>90KB → saved to file; python-grep for
`corruption-probe|invalid-free-span|merge-header-outside|free-list-node-overflow|[FAULT]|[PANIC]`).
`qemu_stop` each instance (unreapable qemu accumulate otherwise). ~3/3 boots crash.
