## Handoff: kalloc/vfs/mm corruption hunt — non-deterministic, ~3 clean/41 boots

### Why every crash clusters at `[ZRAM-SYSFS] disksize=`: resolved (not a zram bug)
Audited zram's `disksize` sysfs handler end to end (`sysfs/block/zram.rs` →
`drv-zram/src/state.rs:195-217` → `state/table.rs:24-59`). Every size
computation (`page_align`, `size/PAGE_BYTES`, chunk count) uses `checked_*`/
`try_from`/`try_reserve_exact` — no unchecked multiply/shift, no raw
`Layout` built from an attacker/external-influenced size. **Not a
size-computation bug.** But this handler DOES trigger something unusual:
a burst of ~7,800 sequential small (page-sized) kalloc allocations in a
tight loop (`slots.resize(count)`, one `Box<[Entry]>` chunk at a time)
plus one ~100-150KB `Vec` growth — by far the largest allocator stress
event naturally occurring anywhere in boot. **This resolves the "why
here" question without needing zram to be buggy**: kalloc's OWN
validation is simply most likely to first stumble onto already-corrupted
free-list state at the moment it's hit hardest, regardless of when or
where the actual corrupting write happened. Detection point ≠ corruption
point — reinforces auditing WRITERS active in this general boot window
(virtio I/O, other concurrent init) rather than zram's own code further.

### 10-sample validation batch complete (post-B1339+B1340+B1341): 1/10 clean — RATE unchanged, but the one clean sample went further than ever before
Ran a full 10 sequential boots after landing all 3 DMA-reuse fixes.
**Result: 1 clean / 9 crashed.** Honest read: 10% is squarely inside the
pre-fix historical baseline (~7-13%, roughly 1 clean per 8-14) — **the
raw crash RATE has not measurably improved**. Do not claim the fixes
solved the corruption; they did not, by this measure.

However, sample 5 (the one clean run) is qualitatively different from
every prior clean sample: it's the first time this whole hunt that a
boot reached a REAL, LIVE GNOME DESKTOP SESSION — `gdm-autologin` PAM
session opened for user `oxide`, `gnome-keyring-daemon started
properly`, `gnome-shell` exec'd and ran its compositor event loop
continuously (`MUTTERWAIT wake` firing on a healthy ~4-5s timer) for
220+ seconds with zero `FAULT`/`PANIC`/`corrupt-`/`invalid-free-span`/
`merge-header-outside` the entire time. Previous best (`debug-
heappoison`'s 723s corruption-free run) hit the separate gdm-hang
blocker before ever reaching a session; this sample went past that too.
`qemu_screen` screenshots showed the text console log rather than a
rendered desktop frame — a separate, non-corruption screendump/scanout-
capture limitation (the trace data proves mutter was genuinely alive
and cycling normally, not hung).

**Conclusion**: B1339/1340/1341 are real, verified-correct fixes that
close a genuine, well-understood class of bug (DMA-write-into-freed-
frame), and the one clean sample suggests that WHEN the remaining
corruption source doesn't fire, the boot now gets meaningfully further
than before. But they have not changed the CRASH FREQUENCY — meaning
either (a) the DMA-reuse class wasn't actually the dominant corruption
source (there's a separate, still-undiscovered mechanism that fires far
more often), or (b) it's one of several roughly-equal-probability
sources and fixing 3 of N doesn't move the aggregate rate much. Samples
1,2,4,6,7,8,9,10 all hit already-known shapes (`invalid-free-span`,
`merge-header-outside`) — no new crash shapes this batch, consistent
with (a): whatever's still firing is one of the ALREADY-CATALOGUED
kalloc-heap corruption instances, not a new one.

### Unifying theory (current best): virtio DMA writes into freed-and-reissued kalloc-heap frames
Every victim this hunt has found (`Dentry`, zram `Slot::Writeback`, kalloc's
own `HoleHdr`, `Vma`, `cgroup`/task-registry nodes) is a KALLOC-HEAP
allocation, and kalloc's heap grows by pulling frames from the SAME buddy
free list virtio DMA buffers cycle through (`alloc_contig`/`free_contig`).
Two real structural bugs found and fixed in this area, BOTH validated
boot-verified-safe but NEITHER sufficient alone (2/2 post-fix boots still
show corruption, each round):
- **B1339 (merged)**: `reset_device` wrote 0 to device status and returned
  immediately, never confirming the device actually quiesced (virtio spec
  requires polling for status readback). `drv-virtio-blk` was freeing
  in-flight DMA buffers right after this unconfirmed "reset."
- **B1340 (merged)**: `alloc_contig`/`free_contig` — unlike the normal
  single-frame path — had ZERO refcount verification at all. Fixed:
  `alloc_contig` now verifies every frame in a run is unreferenced before
  handing it out (skip-and-retry, mirrors the existing single-frame
  integrity check); `reset_device` returns `#[must_use] bool`;
  `drv-virtio-blk`'s cleanup only frees DMA buffers on CONFIRMED reset,
  leaking (not freeing) on an unconfirmed one.
- **B1341 (merged)**: audited every `free_contig` call site in the tree
  for the same class — found a THIRD instance in `drv-virtio-gpu`'s probe
  path: once `ATTACH` succeeds, the device's resource table holds the
  framebuffer's `base_pa` as backing store, but the RAII guard freeing it
  on early-return wasn't disarmed until ALL 5 probe commands succeeded —
  any later command failing froze the buffer via Drop while the device
  still referenced it, no detach ever sent. Fixed: disarm right after
  ATTACH succeeds; a later failure now leaks the page instead of freeing
  a still-referenced one. All other `free_contig` sites audited (blk's
  remaining 3 sites free unpublished-to-device buffers, safe by
  construction) — no more instances of this bug class found.

A virtio device backend runs on a separate QEMU HOST THREAD — genuinely
async relative to the guest even at `smp=1`. If it's still mid-DMA into a
frame that gets freed and reissued to `kalloc_grow`, the write lands on
whatever heap object now lives there — explaining every observed property
at once (non-deterministic, cross-subsystem, clusters near virtio-heavy
boot activity ~20s in). **Both fixes are real and worth keeping, but
corruption persists after each — do not mark this hunt closed based on
either alone.** B1340 validation sample 1 showed a NEW failure mode
(repeated `invalid-free-span` at one address, no panic, boot stalled/
hung — a livelock, not yet understood whether distinct or coincidental).
Next: audit other `free_contig` call sites/paths not yet covered, or
accept the root cause has a further, still-unidentified component.

### Ruled out this hunt (don't re-chase without new evidence)
- **mm-vmm**: exhaustively cleared — `Vma`'s 4 candidate fields (`anon_vma`,
  `file_rmap`, `anon_name`, `uffd`), `AnonVma`/`FileRmap` internals (zero
  back-reference to `Vma`), `VmaTree`'s `BTreeMap` ownership (fork clones
  independent values, no reference held across mutation).
- **cgroup**: `cpu_quota_groups`/`collect_pids` entirely safe Rust, plain
  `BTreeMap` iteration — the disassembly "next"-pointer walk behind the
  recurring `cgroup::tick` crash is libcore's own iterator, not a cgroup bug.
- **Other virtio drivers** (net, vsock, gpu, input, snd): all gate buffer
  reuse on used-ring index advancement, not submission/elapsed-time, and
  free after `reset_device()` returns — inherit B1339/B1340 correctly, no
  independent instance of the blk-class bug found. One low-confidence
  caveat: virtio-gpu's `submit_raw` 1M-poll timeout (`probe.rs:294-301`)
  returns `false` without retry on a real device stall.
- **DMA cache-coherency layer** (`virtio::dma::*`): on x86_64 (this hunt's
  only arch) these are plain atomic fences — correct no-op, x86 DMA is
  cache-coherent. Only relevant on aarch64, never exercised this session.
- **u32-vs-u64 pointer-stride confusion** theory: searched kalloc, PMM,
  page tables, slab, HAL asm — no match found. B1339/1340's DMA theory is
  a better fit (explains the shape as arbitrary device-write content).
- **HAL asm register-clobber** (3rd B1333/B1336-class instance): audited
  all 64 `asm!` sites both arches — none found, all hi:lo packing correct.
- `qemu_break`/`qemu_watch` on kernel VAs: consistently fails ("cannot
  access memory") regardless of boot stage — don't retry, use serial/klog.
- `#UD` Arc-clone refcount-overflow in `dcache`: `vfs/src` has zero raw Arc
  manipulation, external cause. io_uring, futex FUTEX_WAKE_OP, spawn.rs,
  zombies.rs/poll_subs.rs, zsmalloc: all audited clean.

### gdm greeter hang — separate, already-tracked bug, gated by the corruption's crash rate
A `debug-heappoison` boot ran 723s with ZERO memory-corruption faults (2nd
corruption-free boot this hunt, of 30) before hitting an unrelated,
pre-existing bug: `gdm.service` times out (`start operation timed out`).
Prior investigation (commit `6ec8d9b05`) already diagnosed: gdm's
session-wrapper hangs and dies via SIGTERM BEFORE ever calling logind's
`CreateSession`. VT ioctls, DRM node `rdev`, AF_UNIX/epoll edge-loss
already ruled out/fixed (B622, EPOLLET). `debug-futextrace` (traces
`gdm-session-worker`'s futex calls, purpose-built for this) exists but
3 attempts all crashed from the PRIMARY corruption before reaching gdm
(t=18-24s, before the ~45s-later hang window) — gated by crash rate, not
a tool failure; retry needed, not ruled out.

### C176/C177/C179 (merged, kalloc/dentry/zram diagnostics)
C176 widened a silently-gated kalloc diagnostic (was `debug-heappoison`
-only, unlike siblings) — directly enabled capturing real corrupted-node
data for the first time this hunt. C177/C179: two always-on plausibility
guards (`Dentry.sb` Weak-field, zram `Box<Slot>` pointer) — both live,
boot-verified silent, haven't caught the corruption directly yet.

### B1337/B1338 (merged, unrelated real bugs found along the way)
**B1338**: `ptrace_fpu.rs`'s `set_fpregs`/`get_fpregs` had zero tracer/
stopped-state authorization — any task could race a target's own
context-switch FPU save/restore and tear its XSAVE image. Fixed.
`GETREGS`/`SETREGS`/`POKEUSER` have the identical gap, lower priority,
follow-up. **B1337**: the `d_op` corruption guard compared against a
kernel-only VA boundary, misfiring on every hosted test — scoped to
`target_os = "oxide-kernel"`.

### Fast-repro recipe
```
mcp__qemu__qemu_start(arch=x86_64, features="debug-boot,debug-dealloc-diag", smp=1, paused=false)
mcp__qemu__qemu_continue(...)   # times out at 120s (no breakpoint set), boot continues regardless
# wait ~60-90s, then qemu_serial() -> often exceeds tool token cap, saved to a
# file; grep/python-search that file for FAULT/PANIC/KALLOC/corrupt-/invalid-free-span
```
`addr2line -Cfi -e <elf> <rip>` + `objdump -d --start-address=...
--stop-address=...` around the faulting `rip` found every lead every
round. Decode suspicious `[KALLOC]` values as little-endian ASCII AND
check for round power-of-two/systems constants first. `debug-heappoison`
= same repro but ~500-700s, vetoed for iteration except when lighter
techniques are exhausted. Always search for `invalid-free-span`
explicitly — it doesn't always panic, can silently loop/stall instead.

### First command next session
1. 10-sample validation done (above) — crash rate unchanged, no genuinely
   new shapes. Re-focus on the two most frequent recurring shapes THIS
   batch: `invalid-free-span` (samples 1,3,7,9 — 4/9; samples 1 and 3
   ALSO hit a downstream `#PF` with `cr2` near-null shortly after the
   repeated `invalid-free-span` messages — likely a secondary effect of
   something dereferencing a failed `alloc()`'s null result, not a
   second independent corruption) and `merge-header-outside`/`front-
   fragment-failed` (samples 2,4,6,8,10 — 5/9, clean kalloc panics, no
   raw CPU fault). Both are kalloc's OWN validation catching corrupted
   `HoleHdr`s — the writer is still external and unidentified. Notably
   NO `#UD`/`#GP` crashes this batch (the dcache Arc-refcount-overflow
   and cgroup registry-list shapes that dominated earlier rounds) —
   worth checking whether B1339/1340/1341 specifically eliminated those,
   leaving only the kalloc-direct corruption shapes now.
2. Chase B1340 validation's earlier stall/livelock — is `alloc()`
   hitting `invalid-free-span` retried in an unbounded loop somewhere?
3. Retry `debug-futextrace` for the gdm hang now that one boot proved
   it's reachable — try again, gated by crash rate not a tool failure.
