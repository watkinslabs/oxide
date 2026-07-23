## Handoff: kalloc/vfs corruption hunt — non-deterministic, ~1 clean/11 boots

### Headline — READ THIS FIRST
Still not fixed. This round: merged 3 PRs (C176 kalloc diagnostic-gap fix,
B1337 real hosted-test-suite bug fix, C177 new corruption guard) and found
FOUR new precisely-localized crash shapes. All crashes this round hit within
~1s of the same boot event: `[ZRAM-SYSFS] disksize=...` /
`systemd-zram-setup@zram0` / `[SWAPON] activate zram0`. Every fresh boot
samples the SAME instant but a DIFFERENT victim structure — strong evidence
of one still-unidentified wild writer whose target address is
timing/layout-dependent, not a fixed bug in whichever structure happens to
get hit. **Sharpest lead of the whole hunt is the newest one** (see
"NEW crash #3" below): a `kalloc dealloc size mismatch` with byte-exact
alloc/dealloc sizes AND the dealloc caller's return IP, landing in
`drv_zram::writeback::discard_slot` — the first sample all hunt long with
enough precision to name the exact corrupted field.

### NEW crash #3 (this round, SHARPEST lead yet): kalloc dealloc-size mismatch in zram `discard_slot`
`[KALLOC] size-mismatch ptr=ffffffff83978f90 alloc_size=16384
dealloc_size=32 dealloc_caller_ip=0xffffffff8011eedd` → `panic: kalloc
dealloc size mismatch` (`lib.rs:781`, `size_track.rs`'s first-ever fire this
whole hunt — a debug-only tracker recording every alloc's exact carved size
for allocations >=96B, asserting the dealloc's `Layout` matches exactly).
`dealloc_caller_ip` resolves (`addr2line`) to `drv_zram::writeback::
discard_slot` (`writeback.rs:264`). Read the whole path: `discard_slot`'s
`Slot::Writeback { page, data }` arm calls `free_slot_storage(state, &data)`
then falls out of scope, dropping `data: Box<Slot>` — `Box<Slot>`'s
compiler-generated `Drop` always calls `dealloc` with `Layout::new::<Slot>()`
(~32B, matches `dealloc_size` exactly) by construction; there is NO way for
safe Rust to make that call carry a mismatched size **unless the pointer
itself is wrong** — i.e. this `Box<Slot>`'s raw pointer field held an
address that was ACTUALLY a live 16384-byte allocation (very plausibly a
`Vec<u8>` buffer — `io.rs`'s `PreparedSlot::Raw { bytes: page.to_vec(), .. }`
is the only 16384-ish-byte `Vec<u8>` in this driver), not a real `Box<Slot>`
at all. **Confirmed zero unsafe pointer manipulation anywhere on
`Slot::Writeback`**: grepped every reference (`io.rs:60,108`, `slot.rs`
match arms, `tracking.rs:31`, `writeback.rs:272,320,347,355`,
`recompress.rs:50`) — the ONLY construction site is `writeback.rs:320`,
plain safe `Box::new(slot)`. This rules OUT a driver-logic bug and confirms
the SAME external wild-writer theory as every other sample, now localized
to a specific, small, well-typed target: **a `Box<Slot>`'s raw pointer
field, inside a live `Slot::Writeback` value, gets overwritten with an
unrelated live pointer**. This is the most mechanistically precise
description of "the corruptor's blast radius" the whole hunt has produced —
next session should chase this specific field with the same rigor C173/C177
applied to `Dentry` fields (a debug-only guard comparing the `Box<Slot>`
pointer's plausibility, or hardware watchpoint on a captured instance).

### C176 (merged, this round): kalloc `try_merge` diagnostic gap
`try_merge`'s `merge-header-outside` print (holes.rs) was gated to
`debug-heappoison` only, unlike every sibling diagnostic in the file
(`any(debug-heappoison, debug-dealloc-diag)`). A live heap-growth crash
(`growth-register-failed tag=outside-owned-region` → `panic: kalloc grow
region invalid`) traced to this exact silent path: `add_region`'s tail call
into `try_merge` hit the corrupted-successor check and returned
`OutsideOwnedRegion`, but printed nothing under `debug-dealloc-diag` alone —
only the generic caller-side tag survived, no node/bad_next addresses.
Widened the gate (print block + `trail`/`trail_n` locals + `next_seq()`);
`lookup_evicted`/`probe_corruption` stay heappoison-only (own backing state
is heappoison-gated). `cargo check -p kalloc` clean under both feature
combos. **Proved by exhaustive static analysis that `add_region`/
`add_free_region`/`owns_range` have NO internal logic bug** — a fresh
region's `[usable, end)` is mathematically guaranteed to satisfy its own
`owns_range` check immediately after insertion; a rejection can only mean
`self.regions`/a hole's fields changed between validation and use, i.e.
external corruption, not a kalloc bug. Re-ran the repro post-fix; the
SPECIFIC growth-register-failed shape did not recur (non-determinism), but
two OTHER crash shapes did (below) — the diagnostic widening is still
correct and will catch the merge-path corruption next time it recurs.

### NEW crash #1 (this round): `#GP` in FPU-restore during context switch
`[FAULT] vec=0xd (#GP) rip=ffffffff803df8f8` → `sched::live::schedule::
switch::schedule`, disassembles to `xrstor64 (%rcx)`. `#GP` (not `#PF`) on
`xrstor` means the XSAVE state image itself is malformed (bad XSTATE_BV /
reserved bits), not merely unmapped — i.e. a task's `fpu_state` buffer got
corrupted before this restore. New victim structure, same "small-value
stomp into a live struct" shape as everything else this hunt has found.
Not yet chased further (need to find which task, and what wrote into its
`fpu_state`). Relevant: `fpu_state`'s ptrace-authorization gap (found
earlier this hunt, NOT fixed — a missing ptrace-stop check, not a missing
lock) is a plausible but unconfirmed way something writes to a live task's
FPU buffer without holding the right lock.

### NEW crash #2 (this round, STRONGEST lead): `#PF` write to cr2=0x8 in `Arc<Dentry>::drop_slow`
`[FAULT] vec=0xe (#PF) rip=ffffffff805c22c6 cr2=0000000000000008
access=write kind=np`. Disassembly (`Arc<Dentry>::drop_slow`):
```
mov 0x40(%rbx), %rdi
cmp $0xffffffffffffffff, %rdi   ; sentinel check — NOT compared to 0/NULL
je  <skip>
lock decq 0x8(%rdi)             ; faulted here: rdi was 0, not the sentinel
```
Field at offset `0x40` in `Dentry` is `sb: Weak<SuperBlock>` (doc comment:
"NON-owning `Weak`... Default `Weak::new()`..."). Rust's `Weak<T>` encodes
"empty" as a dangling `usize::MAX`-derived sentinel, NOT 0 — matching the
`-1` comparison exactly. The crash means `sb`'s raw pointer word held literal
**0** instead of either the empty-sentinel or a valid `WeakInner` pointer —
drop code treated 0 as "a real pointer", computed `lock decq [0+8]`, faulted.
This is a THIRD independent sample of "a live `Dentry`-adjacent word got
overwritten with a small/zero value" (joins: the `#UD` Arc-strong-count
overflow found earlier this hunt, also inside a `Dentry`'s Arc control
block; and the decoded-string `HoleHdr.size` lead). **Three samples now
converge on Dentry or its immediate neighbors as the recurring victim
region** — the strongest correlation this hunt has produced. Not yet
chased to a writer. C173's Arc-strong-count guard (dcache::hash::
lookup_locked) has still never fired — this NEW sample is a DIFFERENT
field (`sb`, not `d_count`/strong-count) so that guard wouldn't catch it;
consider a matching guard on `Weak` fields if this recurs, or instrument
`Dentry::drop`/`drop_slow` directly since it's not gated behind any debug
feature and runs on every dentry teardown.

### Established, still true (earlier rounds, unchanged)
- Non-determinism is real and reconfirmed every round: identical rebuilds
  produce different crash shapes; single boots lie, need 3-5+ samples.
- `#UD` Arc-clone refcount-overflow abort in `dcache::hash::lookup_locked`
  (rip=0xffffffff805e23b2 across 3 samples): a live Dentry's `ArcInner.
  strong` field corrupted to a small/negative value before Rust's own
  overflow guard trapped. `vfs/src` has zero raw Arc manipulation (grep
  confirmed) — not a vfs-internal bug, an external wild write.
- One sample was confirmed genuine OOM (`memory allocation of 13888 bytes
  failed`), not corruption — zram's `disksize` sizes to ~total RAM
  regardless of `mem=`, so more VM RAM alone doesn't fix it (2/2 crashes
  at `mem=4G` too). De-prioritized.
- Decoded-string lead (`HoleHdr.size` → ASCII `"hreshold"`, matches
  `recompress.rs:28`'s `"threshold"` match arm): every copy path ruled out
  (zero-copy `sys_write`, static klog ring buffer, no `format!`/`String` in
  the zram sysfs chain). Leading theory: a register/stack leak during that
  match's byte-compare, same hazard class as the B1333/B1336 ctxsw
  register-clobber bugs but a different, unfound instance.
- Ruled out as async-write-of-errno-shaped-value sources: io_uring
  (synchronous dispatch, no deferred completion), futex FUTEX_WAKE_OP
  (writes to caller-validated USER address only), sched spawn.rs (writes a
  full struct into a fresh task's OWN slot), zombies.rs/poll_subs.rs
  (safe Vec/Weak patterns, no raw pointer writes).
- zsmalloc (drv-zram) audited clean: generation-checked handle table, no
  raw offset packing, PMM movable-page backed not kalloc-heap backed.
- B1333/B1336 (merged): x86_64 + aarch64 context-switch asm clobbered
  callee-saved registers across an `extern "C"` call boundary without
  declaring them as clobbers (`docs/54§1.4` hazard class) — real bugs,
  fixed both arches, boot-verified, but not the root cause (crashes
  persist after both landed).
- B1334/B1335 (merged): rmap.rs Arc TOCTOU (dead code, unlikely root
  cause), process_vm_readv/writev foreign-AS UAF (live path, plausible,
  unconfirmed).

### Fast-repro recipe
```
mcp__qemu__qemu_start(arch=x86_64, features="debug-boot,debug-dealloc-diag", smp=1, paused=false)
mcp__qemu__qemu_continue(...)   # times out at 120s internally (no breakpoint set), boot continues regardless
# wait ~60-80s (crashes cluster around [ZRAM-SYSFS] disksize=, boot second ~62-79s), then qemu_serial()
# qemu_serial output often exceeds tool token cap -> saved to a file; grep/python-search that file, don't Read it whole
```
`addr2line -Cfi -e <elf> <rip>` + `objdump -d --start-address=... --stop-address=...`
around the faulting `rip` found every lead this round and every round
before it — the single highest-value technique in this hunt. When a
`[KALLOC]` size/address value looks wrong, decode it as little-endian ASCII
(`python3 -c "print((0x...).to_bytes(8,'little'))"`) before anything else.
`debug-heappoison` = same repro but ~500s — vetoed for iteration, one boot
only if truly needed. Always `qemu_list`/`qemu_stop` stale instances first;
`qemu_continue` with no breakpoint set will itself time out at 120s and
move to background — that's expected, not a hang, just re-check
`qemu_serial` after.

### RESOLVED this round: `d_revalidate_drops_stale` hosted-test SIGABRT (B1337)
First attempt at a `sb`-Weak guard appeared to break this test. Root cause
was NOT the guard and NOT a drop-ordering bug: a **pre-existing, unrelated**
false positive in the ALREADY-MERGED `d_op` corruption guard
(`lifecycle.rs`), which compared a live `d_op` pointer against
`hal::USER_VA_END` (a kernel/user address-space split that only exists
under the real `oxide-kernel` target) — a hosted test binary's own statics
sit below that threshold unconditionally, so the guard always misfired.
Confirmed via `git stash`: reproduces on clean `main` with zero unrelated
changes. Fixed (B1337, merged): scoped both guards to
`#[cfg(target_os = "oxide-kernel")]`. Also empirically confirmed (throwaway
hosted `rustc` snippet) that `Weak::<T>::new().as_ptr()` really does return
`usize::MAX`, never `0` — validating the original guard premise. Re-added
the `sb`-Weak guard properly (C177, merged), boot-verified with zero false
positives across a real x86_64 boot.

### First command next session
Chase the sharpest lead (crash #3 above): instrument
`Slot::Writeback.data`'s `Box<Slot>` pointer the same way C173/C177 guarded
`Dentry` fields — a debug-only check at the ONE construction site
(`writeback.rs:320`) and/or right before `discard_slot`'s implicit drop,
comparing the raw pointer against a plausibility check (kernel VA range,
alignment) before trusting it. Since the corruption already has a concrete
byte-exact signature (`alloc_size=16384` vs `dealloc_size=32`), also worth
grepping for what ELSE in the zram writeback path allocates ~16384-byte
`Vec<u8>` buffers (leading candidate: `io.rs`'s `PreparedSlot::Raw { bytes:
page.to_vec(), .. }`) to find the two allocations' relative timing — if
they're adjacent/sequential in the same critical section, that narrows the
writer's window a lot. Re-run the fast repro 2-3x first to see if this
exact shape (`kalloc dealloc size mismatch` in `discard_slot`) recurs
before investing in a guard.
