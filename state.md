## Handoff: kalloc/vfs/mm corruption hunt — non-deterministic, ~1 clean/12 boots

### Headline — READ THIS FIRST
Still not fixed. This round: merged 6 PRs (C176 kalloc diagnostic-gap fix,
B1337 real hosted-test-suite bug fix, C177/C179 new corruption guards, C178
doc, this state.md update pending) and found FIVE new crash shapes across
FOUR different structs (`Dentry`, `Slot::Writeback`, kalloc `HoleHdr`, and
now `mm-vmm::Vma`) — all sharing the same "a pointer field inside a value
with compiler-derived `Drop` gets overwritten, then auto-drop faults
through it" shape. Two guards (C177 `Dentry.sb`, C179 zram `Box<Slot>`) are
now live and boot-verified silent (no false positives across 2-3 real boots
each) — neither has caught the corruption directly yet, but both prove the
specific fields they watch aren't ALWAYS the victim, narrowing where the
next guard should go. Crashes cluster near `[ZRAM-SYSFS] disksize=...` but
NOT exclusively — the newest `Vma` sample hit later, at
`sshd-keygen@ed25519.service` (~27s). One still-unidentified wild writer,
timing/layout-dependent target, not a fixed bug in whichever structure
happens to get hit.

### NEW crash #4 (this round): `#PF` write to cr2=0x0 in `Vma`'s auto-derived `Drop`
`[FAULT] vec=0xe (#PF) rip=ffffffff8060a32b cr2=0 access=write
result=no-mm` → `core::ptr::drop_in_place::<vmm::vma::Vma>`. `Vma` has NO
explicit `impl Drop` (`crates/kernel/mm-vmm/src/vma.rs:313`) — this is
compiler-generated field drop, same mechanism class as the `Dentry.sb` and
`Slot::Writeback.data` samples. Candidate fields (all `Option<Arc<T>>`,
niche-optimized on a null data pointer): `anon_vma: Option<Arc<AnonVma>>`,
`file_rmap: Option<Arc<FileRmap>>`, `anon_name: Option<Arc<str>>`,
`uffd: Option<Arc<dyn UffdContext>>` (fat pointer — data+vtable words could
corrupt independently, a different failure shape than a plain `Arc<T>`).
`result=no-mm` in the fault resolver is itself informative: it means the
faulting write address (0) was classified as needing a process address
space to resolve, i.e. the corrupted pointer decoded to something in the
LOW/user-half range, not a kernel-half garbage value — consistent with a
niche-optimized `Option<Arc<T>>` reading a corrupted-to-something-small (or
exactly 0, if it's the vtable-intact/data-zeroed uffd case) value as "Some"
and dereferencing it. Not yet narrowed to a specific field or given a guard
(unlike Dentry/zram, don't yet have enough precision — 4 candidate fields).
**Audited (this round, clean)**: every write/clone/merge site touching
these 4 fields across the whole kernel tree — `vma/clone.rs` (fork dup),
`vma.rs:463-491` (`clone_subrange`, split/merge/mprotect), `tree.rs`
(`set_uffd_range`, `try_merge_*`), `tree/anon_name.rs`. All are safe
`Arc::clone`/`Option` assignment on owned locals under `AddressSpace.vmas`'
`RwLock` write lock — zero raw-pointer/unsafe manipulation, zero lock-free
access. Rules out an mm-vmm-internal logic bug for this field set (mirrors
the exhaustive `owns_range` proof for kalloc, and the zero-unsafe-code
finding for `Slot::Writeback`) — reinforces the external-wild-writer
theory rather than narrowing to a specific field. One unrelated, non-memory
-safety finding surfaced: `mergeable_with_next` (`vma.rs:427-454`) checks
`anon_name`/`uffd` equality before merging adjacent VMAs but never checks
`anon_vma` — a correctness gap (could silently drop a diverged `anon_vma`
Arc on merge), not a corruption source, worth a separate small fix later.

### NEW crash #3 (RESOLVED into a guard, C179 merged): kalloc dealloc-size mismatch in zram `discard_slot`
`[KALLOC] size-mismatch ptr=ffffffff83978f90 alloc_size=16384
dealloc_size=32 dealloc_caller_ip=0xffffffff8011eedd` → `panic: kalloc
dealloc size mismatch`. Traced to `drv_zram::writeback::discard_slot`
dropping `Slot::Writeback.data: Box<Slot>` — `Box<Slot>`'s
compiler-generated drop always deallocs with `Layout::new::<Slot>()`
(~32B) by construction, so a mismatch there can only mean the pointer
itself was wrong (pointed at what was actually a live 16384-byte `Vec<u8>`
allocation — likely `io.rs`'s `PreparedSlot::Raw { bytes: page.to_vec() }`).
Confirmed zero unsafe pointer code anywhere on `Slot::Writeback` (one
construction site, plain `Box::new`) — rules out a driver-logic bug.
**Guard added (C179, merged)**: plausibility check on the `Box<Slot>`
pointer at the shared `free_slot_storage` choke point (`io.rs`). Boot-
verified silent (no false positive) across 2 real boots; did not catch the
corruption again this round (non-determinism) but is live for next time.

### C176 (merged, this round): kalloc `try_merge` diagnostic gap
`try_merge`'s `merge-header-outside` print (holes.rs) was gated to
`debug-heappoison` only, unlike every sibling diagnostic in the file. A
live heap-growth crash (`growth-register-failed tag=outside-owned-region`)
traced to this exact silent path. Widened the gate to match siblings.
**Proved by exhaustive static analysis that `add_region`/`add_free_region`/
`owns_range` have NO internal logic bug** — a fresh region's `[usable,
end)` is mathematically guaranteed to satisfy its own `owns_range` check
immediately after insertion; a rejection can only mean external corruption
of `self.regions`/a hole's fields between validation and use.

### NEW crash #1 (this round, unchased): `#GP` in FPU-restore during ctxsw
`[FAULT] vec=0xd (#GP) rip=ffffffff803df8f8` → `sched::live::schedule::
switch::schedule`, disassembles to `xrstor64 (%rcx)`. `#GP` means the XSAVE
image is malformed, not unmapped — a task's `fpu_state` buffer corrupted
before restore. Relevant: `fpu_state`'s ptrace-authorization gap (found
earlier this hunt, NOT fixed — missing ptrace-stop check, not a missing
lock) is a plausible but unconfirmed way something writes a live task's
FPU buffer without holding the right lock.

### NEW crash #2 (RESOLVED into a guard, C177 merged): `#PF` write to cr2=0x8 in `Arc<Dentry>::drop_slow`
Disassembly showed `Dentry.sb: Weak<SuperBlock>` (offset 0x40) held raw `0`
instead of `Weak::new()`'s real sentinel (`usize::MAX`, confirmed
empirically via a throwaway hosted `rustc` test) or a valid pointer —
`lock decq 0x8(%rdi=0)` faulted. Third independent sample of a corrupted
`Dentry`-adjacent word (joins the `#UD` Arc-strong-count overflow and the
decoded-string `HoleHdr.size` lead). **Guard added (C177, merged)**: always
-on check in `Dentry::drop` before field-drop runs. Boot-verified silent
(no false positive) across 2 real boots.

### Established, still true (earlier rounds, unchanged)
- Non-determinism reconfirmed every round: identical rebuilds produce
  different crash shapes; single boots lie, need 3-5+ samples.
- `#UD` Arc-clone refcount-overflow abort in `dcache` lookup paths (2 call
  sites hit: `lookup_locked`, `d_lookup_reval`): a live Dentry's `ArcInner.
  strong` field corrupted before Rust's own overflow guard trapped.
  `vfs/src` has zero raw Arc manipulation — not vfs-internal, external.
- One sample confirmed genuine OOM, not corruption; zram `disksize` scales
  to ~total RAM regardless of `mem=`, more VM RAM alone doesn't fix it.
- Decoded-string lead (`HoleHdr.size` → ASCII `"hreshold"`, matches
  `recompress.rs:28`'s `"threshold"` match arm): every copy path ruled out.
  Leading theory: register/stack leak during that match's byte-compare,
  same hazard class as B1333/B1336 but a different, unfound instance.
- Ruled out as async-write-of-errno-shaped-value sources: io_uring, futex
  FUTEX_WAKE_OP, sched spawn.rs, zombies.rs/poll_subs.rs.
- zsmalloc (drv-zram) audited clean: generation-checked handles, PMM
  movable-page backed, not kalloc-heap backed.
- B1333/B1336 (merged): x86_64+aarch64 ctxsw asm register-clobber fixes —
  real bugs, boot-verified, not the root cause (crashes persist).
- B1334/B1335 (merged): rmap.rs Arc TOCTOU (dead code), process_vm foreign-
  AS UAF (live path, plausible, unconfirmed).

### Fast-repro recipe
```
mcp__qemu__qemu_start(arch=x86_64, features="debug-boot,debug-dealloc-diag", smp=1, paused=false)
mcp__qemu__qemu_continue(...)   # times out at 120s internally (no breakpoint set), boot continues regardless
# wait ~60-90s, then qemu_serial() -> often exceeds tool token cap, saved to a
# file; grep/python-search that file for FAULT/PANIC/KALLOC/corrupt-, don't Read whole
```
`addr2line -Cfi -e <elf> <rip>` + `objdump -d --start-address=...
--stop-address=...` around the faulting `rip` found every lead every round.
Decode suspicious `[KALLOC]` values as little-endian ASCII first
(`python3 -c "print((0x...).to_bytes(8,'little'))"`). `debug-heappoison` =
same repro but ~500s — vetoed for iteration. Always `qemu_list`/`qemu_stop`
stale instances first; `qemu_continue` with no breakpoint timing out at
120s is expected, not a hang — just re-check `qemu_serial` after.

### First command next session
1. Narrow crash #4 (`Vma` drop): grep every write path to `anon_vma`,
   `file_rmap`, `anon_name`, `uffd` — B1334 already fixed one raw-pointer
   TOCTOU on `anon_vma` this session (dead code, zero callers) but the
   FIELD itself is still a live candidate for external corruption. Collect
   2-3 more samples before writing a guard (unlike Dentry/zram, not enough
   precision yet to know which field).
2. Re-run the fast repro 3-5x sequentially now that 2 guards are live —
   either one may catch the corruption directly this time.
3. Chase the still-open `fpu_state` XSAVE lead (crash #1) if it recurs.
