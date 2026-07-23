## Handoff: kalloc/vfs corruption hunt — non-deterministic, ~1 clean/9 boots

### Headline — READ THIS FIRST
Still not fixed. This round: closed a real diagnostic gap (C176, merged) and
found TWO new precisely-localized crash shapes, both pointing at small-value
corruption landing in or near `vfs::dentry::Dentry` / its Arc control block —
now THREE independent samples share that shape (strong-count field, `sb`
Weak field, and the earlier decoded-string lead). All crashes this round hit
within ~1s of the same boot event: `[ZRAM-SYSFS] disksize=...` /
`systemd-zram-setup@zram0`. Every fresh boot samples the SAME instant but a
DIFFERENT victim structure — strong evidence of one still-unidentified wild
writer whose target address is timing/layout-dependent, not a fixed bug in
whichever structure happens to get hit.

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

### Tried + reverted this round: `sb: Weak<SuperBlock>` guard in `Dentry::drop`
Attempted a C173-style always-on guard (`Weak::as_ptr(&self.sb) == 0` →
diagnostic + assert) in `crates/kernel/vfs/src/dentry/lifecycle.rs`.
**Reverted** — `cargo test -p vfs --lib` hit `panic in a destructor during
cleanup` / SIGABRT in `dcache::tests::d_revalidate_drops_stale`. Root-caused
this to a **pre-existing, unrelated bug**: the SAME failure reproduces on a
completely clean `main` (verified via `git stash`/`stash pop`) with zero
guard code present. So the guard itself may or may not have been correct
(Rust's `Weak::as_ptr()` dangling-sentinel representation in this toolchain
needs to be verified empirically, e.g. a small hosted unit test asserting
`Weak::<T>::new().as_ptr() as usize` before trusting any assumption about
it — do NOT re-add the guard without that check first), but it's currently
un-testable in isolation because `d_revalidate_drops_stale` already aborts
during cleanup independent of any Weak-related code. **This pre-existing
test failure is itself a new, real, separate lead**: "panic in a destructor
during cleanup" in a dcache test named for exactly the SB/dentry teardown
path this hunt's newest sample (`Arc<Dentry>::drop_slow` `#PF`) also hit —
plausibly the SAME underlying drop-ordering defect, manifesting as a clean
panic in the hosted harness (where UB is caught) versus a wild #PF in the
real kernel (where it isn't). Worth checking whether this hosted test was
green before this session's earlier changes (`git log -p` on
`dcache/tests.rs` / `lifecycle.rs`) or has been broken for longer.

### First command next session
1. `git log --oneline -- crates/kernel/vfs/src/dentry/lifecycle.rs crates/kernel/vfs/src/dcache/tests.rs`
   — find when/whether `d_revalidate_drops_stale` last passed; bisect if
   recently broken, since a REGRESSION here (vs. always-broken) changes
   priority a lot.
2. Read `d_revalidate_drops_stale`'s test body + whatever `SuperBlock`/
   `Dentry` teardown order it exercises — this is now the most concrete,
   ALWAYS-REPRODUCIBLE (not boot-dependent, no QEMU needed) lead in the
   whole hunt. A hosted, deterministic repro beats every boot-based sample
   collected so far; chase this before spending more boot cycles.
3. Once that's understood, THEN decide whether a `sb`-Weak guard (or a
   drop-ordering fix) is the right next code change, and re-verify
   `Weak::as_ptr()`'s actual dangling-value semantics with a throwaway
   hosted unit test before trusting it in guard code again.
