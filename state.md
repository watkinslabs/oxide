## B1315-pmm-reserve-pfn-zero

### Headline — real, named, FIXED bug: PMM was handing out physical page 0
Found and fixed a genuine PMM defect that was also the root cause of the
"ext4 root mount Eio" blocker from the last few rounds (that blocker is
NOT feature-specific flakiness — it was misdiagnosed as such; see below).
With it fixed, got the FIRST 500+ second boot with `debug-stack-guard` +
`debug-heappoison` both active, and captured a fresh, live `kalloc back
fragment invalid` corruption — but the stack-guard canary and the dcache
`d_op` sanity check both stayed silent through it, so THIS occurrence is
neither the stack-guard-wipe class nor the live-Dentry class. `/goal`:
"resolve all issues in handoff.md linux style no hacks no split truth" —
still not met; the corrupting write site is still unnamed.

### The Eio root cause, actually named this time
`crates/kernel/mm-pmm/src/setup/boot_init.rs`'s `init_from_boot_info` built
its `UsableRegion` list straight from the firmware/bootloader memmap with
no reservation of physical page 0. On this boot's memmap, PFN 0 landed in
a `Usable` region and got handed out live by `alloc_raw_frame()` (which
sets refcount=0/mapcount=0 — indistinguishable from "still free" to the
allocator's own integrity checks).

That PA-0 frame was allocated as a virtio queue's `driver_pa` (avail ring)
for PCI `0:1.0` (the ROOT virtio-blk device — cap matches the 2.8G root
image). `crates/kernel/pci-boot/src/virtio_transport.rs:91` then does `if
... || q0.driver_pa == 0 { return None }` — PA 0 is treated as a null/
invalid sentinel THERE (and in several other spots: `require_queue`,
`frame_ptr` checks). So the root disk's queue setup silently "failed" (by
convention, not by real hardware failure), `init_blk()` bailed with no log
line at all, and the ROOT block device never registered. `by_serial
("oxide-root")` then missed and `kmain::rootfs::init` fell back to
`first_device()` — the much smaller `oxide-home` disk — and mounting THAT
as root ext4 correctly failed: `Eio`.

Confirmed via two identical 100%-reproducible boots (not flaky): both
showed exactly one `virtio-blk-modern` init log line (for `0:2.0`, cap_sec
matching the home image) despite TWO virtio-blk PCI functions doing full
virtqueue setup. `0:1.0`'s queue-0 trace showed `driver_pa=0000000000000000`
verbatim. This also explains the earlier apparent "debug-smp causes Eio"
and "debug-stack-guard also causes Eio" correlations from prior rounds —
both were coincidence; the real trigger is memmap-dependent (whether PFN 0
happens to land in a Usable region for that particular boot's firmware map),
not feature-dependent. That is now corrected in the record.

### The fix
`crates/kernel/mm-pmm/src/setup/boot_init.rs`: clamp `start_pfn` to at
least 1 when building each `UsableRegion`, matching Linux's unconditional
`memblock_reserve(0, PAGE_SIZE)` — PFN 0 must never enter the buddy free
list, full stop, regardless of what the firmware memmap claims. This is
the correct fix location and shape: one canonical place (PMM boot-time
region construction), not a scattered set of "treat PA 0 as invalid" patches
at each of the several call sites that already (accidentally) do that.
Hosted `cargo test -p pmm`: 123/123 pass. Both arches build clean.

### Boot-verified: Eio is gone
Two boots post-fix both sailed straight past the point that killed 100% of
prior attempts (was: guaranteed panic at ~6s). One ran 513 seconds deep into
real systemd/GNOME userspace (`upowerd`, `accounts-daemon`, `logind`,
`udisksd`, multiple real `EXECLOAD`/`elf-load` cycles) before hitting the
`kalloc back fragment invalid` corruption again — this is the deepest and
first Eio-free run of the corruption-hunt boots this session.

### This occurrence's forensics (new data point, not yet explained)
`[KALLOC] merge-header-outside node=ffffffff81c924c0 node_size=0x45ff100000
bad_next=0x00aaaaaa`, at `crates/shared/kalloc/src/holes.rs:592`. Checked
every diagnostic wired up so far against this specific event:
- `debug-stack-guard`'s canary (`Task::debug_check_canary`) — silent, never
  fired. Rules out this occurrence being the literal "Task kernel-stack
  guard-canary wipe" from the original handoff.md wording, at least for
  this instance of the bug.
- dcache `[DENTRY-BISECT]` periodic `d_op` sanity sweep — silent, never
  fired. Rules out the live-Dentry corruption class for this occurrence.
- `HoleList::lookup_evicted` (EvictHistory / free_ip provenance) — empty.
  This corrupted node was NOT a previously-freed/quarantined block; it was
  sitting live on the free list when its header got trashed. A third,
  distinct victim shape from the zram/ext4/Dentry victims found earlier.
- Redzone check (B1313) — not applicable here (redzones guard allocated
  blocks' tails, not free-list header memory), consistent with the earlier
  "not linear overflow" finding.
GDB bridge went unresponsive after the panic (`qemu_interrupt`/
`qemu_backtrace`/`qemu_regs` all timed out — 30s, no `*stopped`) so no live
backtrace of the actual corrupting call site was captured this round; only
the klog panic dump. Instance was stopped rather than burning more time
fighting a dead debug session (per "no repeated boot-per-hypothesis" spirit
— a wedged GDB bridge is a tooling problem, not a hypothesis to keep
re-testing blind).

### Session summary — what's confirmed vs still open
**Confirmed, real, independent fixes this session (all merged):**
- **B1309** (#3735): `HoleList::validate()`/`dump()`, `try_merge` merge-trail,
  `KAlloc::periodic_validate`, PMM `kalloc_grow` hardening asserts.
- **B1310** (#3736): fixed a confirmed self-deadlock in `poison.rs`. Added
  `HoleList::EvictHistory`.
- **B1311** (#3740): real x86_64 `free_ip` capture. `Dentry::drop` `d_op`
  canonical-address hardening.
- **B1312** (#3742): dcache-wide periodic `d_op` sanity sweep.
- **B1313** (#3744): wired dead redzone code; ruled out linear overflow.
- **B1314**: decoupled stack-guard canary check from `debug-smp`.
- **B1315** (this one): named + fixed the real PMM PFN-0 double-meaning bug;
  boot-verified Eio-free deep boots now possible; captured a third distinct
  corruption-victim shape (free HoleList node header, no provenance).

**What's been RULED OUT for the actual corruptor** (high confidence):
single-subsystem buggy frees (zram, ext4, dentries); linear/adjacent-neighbor
buffer overflow; `as_teardown`/PMM growth as primary cause; the highest-
suspicion `Arc::from_raw`/`into_raw` sites kernel-wide; today's stack-guard
canary and dcache d_op sweep for THIS SPECIFIC occurrence (still worth
running again — one clean miss isn't proof for every occurrence, only this
one); `debug-smp`/`debug-stack-guard` as causes of Eio (was the PMM bug).

**Still genuinely open**: the actual writer. Now with Eio fixed, deep
Eio-free boots are repeatable — the next session should get several more
data points on this corruption before concluding anything about which
diagnostic reliably catches it.

### Concrete next step
1. Re-run the same boot (`debug-boot,debug-heappoison,sched/debug-stack-guard`)
   now that Eio is fixed — it's no longer a blind retry, it's exercising a
   now-repeatable, deep, Eio-free path. Get 2-3 more corruption samples and
   check whether stack-guard/dentry-sanity/EvictHistory ever DO fire on a
   different occurrence (this round's one miss doesn't clear those checks
   for good).
2. Fix or route around the dead GDB bridge on panic — a live backtrace at
   the exact `try_merge` call site would likely name the actual caller
   immediately. Worth checking whether the panic path's `cli`+`hlt` loop can
   be given a debug int3 instead, or whether the gdbstub bridge itself needs
   a restart between the panic and the interrupt attempt.
3. `net/vsock/transaction.rs`, `console/*`, `serialtty/lib.rs`,
   `syscalls/{056_clone,060_exit}.rs`, `ipc/live/futex/{wait,waitv}.rs` —
   still only skimmed, not exhaustively audited.
4. If several more Eio-free boots all show the free-list-header victim shape
   (this round's) rather than the earlier Dentry/zram/ext4 shapes, that's a
   real pattern shift worth chasing on its own — could mean the earlier
   "victims found via EvictHistory" were themselves partly an artifact of
   Eio cutting boots short before this class had a chance to appear.
5. This bug has now resisted this session's extensive live+static effort AND
   multiple PRIOR sessions with dedicated agent audits (per
   `gnome-blocker-refcount-uaf` memory) — treat it as genuinely hard, not one
   grep or one boot away from resolution.

### Housekeeping
- Kill stale `qemu-system-x86_64` before new boots.
- Branches this session: B1309 (#3735), B1310 (#3736), B1311 (#3740),
  B1312 (#3742), B1313 (#3744), B1314 (#3746), B1315 (this one).
