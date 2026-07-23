## Handoff: kalloc/vfs/mm corruption hunt — non-deterministic, ~2 clean/28 boots

### gdm greeter hang: separate, already-tracked bug — investigation gated by the corruption's crash rate
The `debug-heappoison` clean boot above surfaced a SEPARATE, pre-existing,
already-tracked bug: `gdm.service` times out (`start operation timed out.
Terminating`) even with zero memory corruption. Prior investigation
(commit `6ec8d9b05`, git history — not `scratch/`, that ledger was
deleted) already diagnosed: gdm's session-wrapper (exec'd via `/proc/
self/fd/9`) hangs and dies via SIGTERM (`code=271`) BEFORE ever calling
logind's `CreateSession` — no `gnome-shell` ever spawns, no SCM_RIGHTS
pidfd relay fires. VT ioctls, DRM node `rdev`, and AF_UNIX/epoll edge-loss
were all already ruled out/fixed in earlier work (B622, EPOLLET fix).
`debug-futextrace` (kernel feature, traces `gdm-session-worker`'s futex
calls specifically via klog — purpose-built for this exact investigation)
exists but was never run to completion: **3 attempts this round, all 3
crashed from the ONGOING memory corruption before ever reaching gdm**
(t=18-24s each, before the ~45s-later hang window). This sub-investigation
is gated by the primary bug's ~90%+ crash rate — reaching gdm AND
surviving the full hang window needs ~70+s corruption-free, a much higher
bar than the usual ~20s zram-setup crash cluster. Next session: either
fix enough of the primary corruption to reliably reach this window, or
accept several more `debug-futextrace` retry attempts (non-deterministic,
may need 5-10+ tries) — do not treat 3 failed attempts as ruling anything
out, the tool/approach itself is sound and untested, only unlucky so far.

### 2nd-ever corruption-free boot, under `debug-heappoison` (this round)
Ran the rare, slow (`~723s` this run) `debug-heappoison` diagnostic boot —
justified because 7+ subsystems were audited clean and lighter techniques
were exhausted. Result: **zero kalloc/memory-corruption panics or faults
for the ENTIRE run**, reaching `gdm.service`, then hit the
**already-documented, pre-existing, SEPARATE** greeter-hang issue (`gdm.
service: start operation timed out` — matches known prior gdm busy-loop/
SIGTERM/crash-loop blocker exactly, see next section) — NOT new
corruption. 2nd corruption-free boot this hunt (of 25). Two
non-exclusive readings: `debug-heappoison`'s overhead changes timing
enough to dodge the race (informative, reinforces the timing-race
theory), or genuine luck — either way NOT strong evidence of a fix (one
clean sample proves nothing; need 3-5+). Confirms `debug-heappoison`'s
own diagnostics add no false positives across a full run when the race
doesn't fire.

### B1339 VALIDATED, NOT SUFFICIENT ALONE: 2/2 post-fix boots still crash
Ran 2 sequential boots against the merged B1339 fix. **Both still crash.**
Sample 1: the EXACT SAME `sched::cgroup::tick` `#GP` on
`rcx=r14=0x7fffffff00000000` as the pre-fix sample, at nearly the same
`rip` (`ffffffff803e52aa` vs `803e4e9a`) — B1339 did NOT eliminate this
specific corruption instance. Sample 2: a DIFFERENT shape (`#GP` at
`rip=ffffffff805c27b8`, preceded by 3x `[KALLOC] invalid-free-span
size=0` on the same address — an already-known shape). **Conclusion**:
B1339 is a real, correctly-fixed bug (confirmed by boot-verify: no
regressions, closes a genuine spec-violation race) but is NOT the sole
corruption source — either it's one of several independent DMA/device
races, or the actual root cause lies elsewhere and B1339 was a false
positive for causality despite being a real bug in its own right. Do NOT
mark this hunt closed based on B1339 alone. Next session: keep hunting —
the reset-vs-DMA pattern is still worth checking in OTHER drivers (not
just virtio), but treat it as one fix among several needed, not the fix.
**Other virtio drivers audited (this round, clean)**: net, vsock, gpu,
input, snd all gate buffer reuse strictly on used-ring index advancement
(not submission/elapsed-time), and every shutdown/uninstall path frees
buffers AFTER `reset_device()` returns — they inherit B1339's fix
correctly, none has its own independent instance of the blk bug class.
One low-confidence caveat: virtio-gpu's `submit_raw` 1M-poll timeout
(`probe.rs:294-301`) returns `false` without retry on a real device stall
— could theoretically race, but needs sustained device stall, not normal
boot timing. **DMA cache-coherency layer checked, not the cause**:
`virtio::dma::clean_to_device`/`invalidate_from_device` — on x86_64 (the
only arch this whole hunt's repro uses) these are plain atomic fences, a
correct no-op-modulo-fence (x86 DMA is cache-coherent); the `dc cvac`/`dc
ivac` cache-line-flush instructions only exist in the aarch64 branch, not
relevant to any sample collected this session. Virtio subsystem now
thoroughly audited end to end; the persistent corruption most likely has
a genuinely different root cause — check PMM frame reuse/allocator logic
unrelated to virtio next, or continue the `sched::cgroup::tick` shape's
own call chain (`cgroup::cpu_quota_groups` → `Tree`'s `BTreeMap<u64,
Node>` — the disassembly's "next"-pointer list walk may be libcore's own
`BTreeMap` iterator internals, not application code; a corrupted BTreeMap
node here would be a `cgroup` crate `Node`/tree bug, not yet audited).

### STRONGEST CANDIDATE ROOT CAUSE FOUND + FIXED THIS ROUND: B1339 virtio reset-vs-DMA race
`reset_device` (`crates/drivers/virtio/src/common_cfg.rs`) wrote 0 to
`CFG_DEVICE_STATUS` and returned immediately — never confirming the device
actually completed reset (virtio 1.2 §4.1.4.3.1 requires waiting for a
status readback of 0). `drv-virtio-blk`'s `cancel_owned_requests()` frees
in-flight DMA bounce buffers right after `reset_common_cfg()`, on a SAFETY
comment's UNENFORCED assumption that reset means the device stopped
touching them. If QEMU's backend is still mid-DMA when that free runs, the
freed physical page re-enters the PMM pool live, and the device keeps
writing into it — a genuine DEVICE-SIDE wild write into WHATEVER the
allocator next hands that page to, completely bypassing every kernel-code
audit this hunt has done. Best-fitting explanation for the whole pattern:
non-deterministic (DMA/reset timing race), cross-subsystem (device doesn't
care what's living in that page next), clusters near zram/virtio-heavy
boot activity (~20s, matches every crash cluster). **Fixed (B1339,
merged)**: bounded status-readback poll, shared by every virtio driver
(blk, gpu, input, net, vsock, snd) so it closes this race everywhere.
Boot-verified: all virtio devices init at unchanged timing, no
regressions. **Not yet proven to be THE fix** — next session needs a real
sample count (10+ sequential boots) to see if the clean/crash ratio
shifts before declaring this closed.

### Corroborating theory: "high-32/low-32-zero" shape across 5 subsystems
Two independent samples share an exact bit signature: `d_op` corrupted to
`0x100000000` (high=1, low=0) and a `sched::cgroup::tick` list-walk `#GP`
on `0x7fffffff00000000` (high=`i32::MAX`, low=0, non-canonical). Same
shape, 5th unrelated subsystem (registry list node, after `Dentry`,
`Slot::Writeback`, kalloc `HoleHdr`, `Vma`) — kalloc/heap-allocation is the
only thing they share. Searched for a u32-vs-u64 pointer-stride confusion
bug (the natural explanation for this shape) across kalloc, PMM, page
tables, slab — none found (all consistent `size_of::<T>()`-derived
strides). Searched HAL asm for a 3rd B1333/B1336-class register hazard —
none found (all hi:lo MSR/TSC/XCR0 packing internally consistent). B1339
(virtio DMA-after-free) is a BETTER fit than either theory since it
explains the shape as arbitrary device-write content, not a specific
kernel bug pattern — treat the stride-confusion angle as secondary now.

### `merge-header-outside` data (2 samples, via C176's diagnostic fix)
Sample 1: `bad_next` bytes `03 8f 04 8e 05 8d 06 8c` (ascending/descending
structure). Sample 2 (different boot): `0d 5d 02 86 10 0e 41 00` (no
matching structure) — rules out one fixed deterministic pattern; consistent
with device-write-content-is-arbitrary (B1339 theory). Both `HoleHdr`
fields garbage together each time (bulk overwrite). `try_merge`'s coalesce
logic confirmed correct (not a kalloc bug). Ruled out unzeroed fresh PMM
memory. Sample 2's `merge-header-outside` was non-fatal (boot continued);
a LATER, separate `growth-register-failed` killed it — heap degrades
progressively across multiple independent events per boot.

### Guards live, boot-verified silent (haven't caught corruption directly yet)
C177 (`Dentry.sb` Weak-field check in `Dentry::drop`) and C179 (zram
`Box<Slot>` pointer plausibility check at `free_slot_storage`) — both
merged, silent across 2-3 real boots each, no false positives.

### Other fixes this round (merged)
**B1338**: `ptrace_fpu.rs`'s `set_fpregs`/`get_fpregs` had zero tracer/
stopped-state authorization — any task could `PTRACE_SETFPREGS` any pid,
racing the target's own context-switch `fpu_save`/`fpu_restore` on the
unlocked `fpu_state` cell, tearing its XSAVE image (`#GP`-at-`xrstor64`).
Fixed: both require `traced_by == caller` AND `state() == Stopped` now.
`GETREGS`/`SETREGS`/`POKEUSER` have the identical gap, lower priority
(don't race hardware save/restore), follow-up. **B1337**: the pre-existing
`d_op` corruption guard compared against `hal::USER_VA_END`, a kernel-only
invariant, so it always misfired on hosted tests (SIGABRT'd the whole
`vfs` suite) — scoped to `target_os = "oxide-kernel"`. **C176**: kalloc
`try_merge`'s diagnostic print was gated `debug-heappoison`-only unlike
siblings — widened, directly enabled capturing the merge-header-outside
samples above. Also proved `add_region`/`add_free_region`/`owns_range`
have no internal logic bug (mathematically can't fail on a fresh region).

### mm-vmm fully cleared (Crash #4: `#PF` cr2=0x0 in `Vma`'s auto `Drop`)
`Vma` has no explicit `Drop` (compiler field-drop over 4 `Option<Arc<T>>`
fields). ALL cleared: every write/clone/merge site is safe `Arc::clone`
under the tree's `RwLock`; `AnonVma`/`FileRmap` hold zero back-reference
to `Vma`; `uffd` has zero trait implementers anywhere (dead field);
`VmaTree`'s `BTreeMap<_, Vma>` ownership is sound (fork clones independent
values, no reference held across mutation). mm-vmm exhaustively cleared —
reinforces external-writer theory. Side-finding: `mergeable_with_next`
never checks `anon_vma` equality before merging (correctness gap, not
corruption, separate small fix later).

### Established, still true (condensed)
Non-determinism reconfirmed every round. `#UD` Arc-clone refcount-overflow
abort in `dcache` (2 call sites): `Dentry.ArcInner.strong` corrupted before
Rust's own guard trapped; `vfs/src` has zero raw Arc manipulation. One
sample = genuine OOM (zram `disksize` scales to ~RAM). Decoded-string lead
(`HoleHdr.size` → `"hreshold"`, `recompress.rs:28`, every copy path ruled
out). Ruled out as sources: io_uring, futex FUTEX_WAKE_OP, spawn.rs,
zombies.rs/poll_subs.rs, zsmalloc. B1333/B1336 (merged): real ctxsw
register-clobber fixes, not root cause on their own. B1334/B1335 (merged):
rmap TOCTOU (dead code), process_vm foreign-AS UAF (unconfirmed).
`qemu_break`/`qemu_watch` on kernel VAs consistently fails ("cannot access
memory") regardless of boot stage — don't retry, GDB bridge unreliable
here; stick to serial/klog forensics (the hunt's actual proven method).

### Fast-repro recipe
```
mcp__qemu__qemu_start(arch=x86_64, features="debug-boot,debug-dealloc-diag", smp=1, paused=false)
mcp__qemu__qemu_continue(...)   # times out at 120s (no breakpoint set), boot continues regardless
# wait ~60-90s, then qemu_serial() -> often exceeds tool token cap, saved to a
# file; grep/python-search that file for FAULT/PANIC/KALLOC/corrupt-, don't Read whole
```
`addr2line -Cfi -e <elf> <rip>` + `objdump -d --start-address=...
--stop-address=...` around the faulting `rip` found every lead every
round. Decode suspicious `[KALLOC]` values as little-endian ASCII AND
check for round power-of-two/systems constants first. `debug-heappoison`
= same repro but ~500s, vetoed for iteration. `qemu_list`/`qemu_stop`
stale instances first.

### First command next session
1. `cgroup::cpu_quota_groups()`/`collect_pids` checked this round: entirely
   safe Rust (plain `BTreeMap` iteration, no unsafe) — the disassembly's
   "next"-pointer walk is libcore's own `BTreeMap` iterator, meaning a
   corrupted NODE (kalloc-heap memory), not a cgroup logic bug. Virtio and
   cgroup are now both cleared; check PMM frame reuse/allocator logic next
   (double-issue of a frame, missing refcount check on reuse).
2. Retry `debug-futextrace` for the gdm hang (3/3 attempts crashed early
   this round from the primary corruption, not a technique failure).
3. Continue collecting samples; C177/C179 guards remain live.
