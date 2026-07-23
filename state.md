## Handoff: heap corruptor = VIRTIO USED-RING UAF (root cause decoded); io_uring fix insufficient

### Headline
Branch `B1343-virtio-used-ring-uaf-rootcause` (this doc + CLAUDE.md lesson 11).
**io_uring fix (B1342, in main) is NOT the ~90% corruptor** — measured 3/3 crash
this session. **Decoded the corrupt free-list-header bytes: they are a virtio
USED RING.** The corruptor is a virtqueue RING frame freed-and-recycled while a
device still DMA-writes completions into it. No code fix landed yet (evidence-based
narrowing per Discipline lesson 6; the fix is a multi-site change needing a
confirm-which-device trace + boot verification the corruption crash muddies).

### Rate measurement (post-B1342, fast build `debug-boot,debug-dealloc-diag`, kvm, smp=1)
- boot-2: CRASH — `[KALLOC] invalid-free-span` panic (kalloc grow region invalid), victim = static-heap free-list node.
- boot-3: CRASH — `#GP` in `sched::live::schedule::switch::schedule` (victim = runqueue/Task).
- boot-4: CRASH — `merge-header-outside node_size=0x200000000 bad_next=0x300000000`.
- **0 clean / 3 crashed.** All clustered at `[ZRAM-SYSFS] disksize=` (heaviest alloc burst = detection point, NOT corruption point — state.md history). None reached login/gdm/gnome. Rate unchanged from the pre-B1342 ~90%.
- (boots 1 = my error: forgot `qemu_continue` after `qemu_start(paused=false)` → VM sat stopped-under-gdb, empty serial looked like a GRUB hang. ALWAYS `qemu_continue` after start.)

### THE BREAKTHROUGH — decode the corrupt bytes (CLAUDE.md lesson 11)
boot-4 header `bad_next=0x0000000300000000 node_size=0x0000000200000000`, little-endian =
`00 00 00 00 03 00 00 00 | 00 00 00 00 02 00 00 00` = **virtio `vring_used`**:
`flags=0, idx=0, ring[0]={id:3,len:0}, ring[1]={id:2,len:0}`. The device wrote
completed descriptor IDs 3 and 2 into a used ring sitting in a recycled kalloc block.
This **unifies every prior incidental `X<<32` value** (`1<<32`,`2<<32`,`3<<32`,`0x7fffffff<<32`)
as small descriptor ids/lengths landing in the high half of u64 free-list-header fields.
Victim moves with heap layout (kalloc node / runqueue / registry Weak) — same corruptor.

### Why B1339/1340/1341 didn't move the rate
They fixed data-BUFFER quiescence. The victim is the **virtqueue RING frame**. Raw
ring/DMA frames have **refcount 0** (fan-out Finding 2) → B1340's in-use guard can't
protect them. Freed ring frame → buddy → `kalloc_grow` → KHEAP → device's late
used-ring DMA corrupts a free-list header.

### Narrowed suspect (prime) + fix direction
Ring-frame free paths (`crates/kernel/pci-boot/src/virtio_transport/msix.rs`):
- `reset_failed_probe`→`virtio::reset_device` — **SAFE** (`reset_device` `common_cfg.rs:206` writes status=0, spins until read-back 0 = confirmed quiescence). Also queue-alloc rollback (`virtio/src/queue_cfg.rs:150-159`) frees BEFORE programming = safe.
- **`release_transport_record` (msix.rs ~230, via `unpublish_transport_record`) — PRIME SUSPECT.** Frees `vring_frames` relying on a bare SAFETY-comment assumption ("Child remove resets/quiesces the device before unpublishing") but does **NOT** call `reset_device` itself; callers `unpublish_transport_mmio` (`virtio_drv/probe.rs:172`) / `unpublish_transport` (`virtio_bus.rs:95`) don't visibly reset. Descriptor ids 2,3 = a device that COMPLETED requests (published+active), consistent with an unpublish, NOT a failed probe.
- Alternative mechanism: buddy double-hands a live refcount-0 ring frame to `kalloc_grow` (B1340 class, unprotected raw frames).

**Fix:** thread `cfg_va` into `TransportRecord`; in `release_transport_record` call
`virtio::reset_device(cfg_va)` BEFORE `mappings.unmap_all()`/`free_one_frame` — never
free a device-DMA'd frame on a caller-assumed quiesce (mirror the failed-probe path).

### First task next session
1. **Confirm the path is hit:** add a one-shot klog trace at `release_transport_record` (bdf + vring_frames.len) + `unpublish_transport*`; boot once (`qemu_start` THEN `qemu_continue`); grep serial — does a virtio device unpublish mid-boot before the crash? If yes → implement the reset-before-free fix, boot ≥4× to measure new rate. If NO unpublish fires → the mechanism is the buddy double-hand (B1340 class); pivot to instrumenting `kalloc_grow`'s incoming region vs live ring PAs.
2. Boot recipe: `qemu_start(x86_64, features="debug-boot,debug-dealloc-diag", paused=false)` → `qemu_continue` (times out 120s, expected) → `qemu_serial` (>90KB → saved to file; python-grep for `invalid-free-span|merge-header-outside|[FAULT]|[PANIC]`). `qemu_stop` each instance (unreapable qemu accumulate otherwise).

### Secondary finding (NOT the corruptor) — real IRQ-safety DEADLOCK bug (3-agent fan-out)
Timer ISR `tick_poll_combined` (hard-IRQ IF=0, `kmain/hooks.rs`) touches `REG`/`ZOMBIES`/
`WAKE_LISTS`/`rq.inner`/`child_sigq` via **plain `.lock()`** (not `lock_irqsave`); the
`sti; do_softirq()` window (`lapic/dispatch.rs:137`) lets a nested timer IRQ re-enter it.
All 3 agents: this is a same-CPU spinlock **self-deadlock/hang** (explains state.md's
"livelock/stall" variants + `wake_wait4_parent` taking `rq.inner.lock` from IF=0, violating
the "never take rq lock from timer path" contract) — **NOT a torn write** (a correct
spinlock nested on one CPU spins forever; it cannot half-write a Vec). Fix (future PR):
move `reap_orphans`+`tick_wake_expired` off hard-IRQ into the ktimers kthread via
`register_periodic` (`sched/lib.rs:187`), OR gate the nested tick with `!in_serving_softirq()`
(`lapic/dispatch.rs:126`) + `WAKE_LISTS` → `lock_irqsave`. Real bug, separate lane.
