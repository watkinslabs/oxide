## Handoff: kalloc/vfs/mm corruption hunt — non-deterministic, ~1 clean/19 boots

### BIGGEST LEAD YET (end of this round): `d_op` corrupted to EXACTLY 4 GiB
The pre-existing `corrupt-d-op` guard (in `Dentry::drop`, scoped to real-
kernel-only by B1337 this round) fired for the FIRST TIME this whole hunt:
`[DENTRY] corrupt-d-op addr=0x0000000100000000` → `panic: dentry d_op
corrupted` (`lifecycle.rs:63`). `0x100000000` = exactly `1 << 32` = **4
GiB**, not random garbage — a suspiciously round systems constant. This
number is NOT arbitrary in this codebase: `mm-pmm/src/lib.rs:56-57`:
`MAX_ORDER: u8 = 20` is documented "4 KiB (order 0) up to **4 GiB** (order
20)" — `PAGE_SIZE(4096) << MAX_ORDER(20) == 2^32 == 0x100000000` EXACTLY.
Searched every `<< 32` / 4GiB-literal site in the tree — no direct hit yet
(all `<< 32` hits are legitimate hi/lo packing unrelated to vfs), but
`kalloc_grow`'s (`pmm/boot.rs`) own size/order computation
(`pages.next_power_of_two()` → `pages.trailing_zeros() as u8` → `pages *
PAGE_SIZE`) is the most plausible place a CORRUPTED `Layout::size()` could
round up to exactly `2^20` pages and yield this exact byte count. **Next
session's #1 priority**: trace whether this 4GiB VALUE (not a pointer, a
BYTE COUNT) could get returned/stored somewhere a pointer is expected —
e.g. a generic error/size-vs-pointer conflation in an allocator path, or
`kalloc_grow` returning `(addr, size)` with `size`/`addr` swapped under
some rare branch. Also check any OTHER subsystem computing a byte-size via
`MAX_ORDER`/order-20 math near dentry allocation. Far more actionable than
the `03 8f 04 8e...` byte-pattern lead below, which remains unexplained.
**Checked and ruled out (this round)**: a 3rd instance of the B1333/B1336
asm register-clobber/width-confusion class — audited all 64 `asm!` sites
across x86_64+aarch64 HAL, every hi:lo u64↔u32 pack (MSR/TSC/XCR0) is
internally consistent, no `mul`/`div`/`adc` anywhere in the HAL asm that
could leak a stray high-32 value. Next: hardware watchpoint (`qemu_watch`)
on a live `Dentry.d_op` field address, now that we have a concrete field
to target instead of B1332's earlier untargeted attempt.
**2nd `merge-header-outside` sample** (different boot): `bad_next=
0d5d02861 0e4100` — does NOT match sample #1's ascending/descending byte
structure, ruling out a single fixed deterministic corruption pattern.
Also notable: this boot's `merge-header-outside` was non-fatal (recovered,
boot continued) while a LATER, separate `growth-register-failed` panic
killed it — suggesting the heap degrades progressively across multiple
independent corruption events per boot, not one atomic corruption→crash.

### Headline
Still not fixed. This round: merged 11 PRs — 3 real bug fixes (C176 kalloc
diagnostic-gap, B1337 hosted-test false-positive, **B1338: a genuine
ptrace-FPU data race, root-caused AND fixed** — `set_fpregs`/`get_fpregs`
had zero tracer/stopped-state authorization, letting any task tear a live
target's XSAVE image via `resolve_user_pid`+unchecked write, producing the
`#GP`-at-`xrstor64` crash), 2 corruption guards (C177 `Dentry.sb`, C179
zram `Box<Slot>`, both boot-verified silent, live for next occurrence),
plus docs/audits. Six crash shapes found across four structs (`Dentry`,
`Slot::Writeback`, kalloc `HoleHdr`, `mm-vmm::Vma`), all sharing "a pointer
field inside a value with compiler-derived `Drop` gets overwritten, then
auto-drop faults" — mm-vmm exhaustively audited and cleared (fields,
`AnonVma`/`FileRmap` internals, `uffd` dead-code, `VmaTree` ownership all
sound), reinforcing one external wild-writer theory. Crashes cluster near
`[ZRAM-SYSFS] disksize=...` but not exclusively.

### `merge-header-outside` data captured (this round, via C176's fix)
```
[KALLOC] seq=0 merge-header-outside node=ffffffff819b5400
  node_size=181841094446025728 bad_next=038f048e058d068c
[KALLOC] merge-trail addr=ffffffff817b7d98 size=4096 (x2 more, then size=64)
[KALLOC] front-fragment-failed tag=outside-owned-region cur_addr=ffffffff8154c4e0 front_pad=32
```
Both `HoleHdr` fields garbage together (bulk overwrite, not single-pointer
stomp). `bad_next` bytes `03 8f 04 8e 05 8d 06 8c`: even bytes ascend, odd
descend — distinct structure, not random/ASCII/kalloc's own poison bytes.
`try_merge`'s coalesce logic (`holes.rs:640-641`) confirmed correct — not a
kalloc bug. Ruled out unzeroed fresh PMM memory (node was a previously-
valid tracked hole). Pattern search (IDT/IRQ, PCI, table-init loops,
SMP/APIC, sched priority tables) found no match to the byte pattern; not
yet checked: Limine-handoff structs, ACPI/MADT, `crates/kernel/firmware/`.

### Crash #4: `#PF` cr2=0x0 in `Vma`'s auto-derived `Drop` — mm-vmm fully cleared
`core::ptr::drop_in_place::<vmm::vma::Vma>` faulted; `Vma` has no explicit
`impl Drop` (compiler field-drop). Candidates were `anon_vma`, `file_rmap`,
`anon_name`, `uffd` (all `Option<Arc<T>>`/niche-optimized). **All 4
cleared**: every write/clone/merge site (fork, `clone_subrange`,
`set_uffd_range`, `set_anon_name_range`) is safe `Arc::clone` under
`AddressSpace.vmas`' `RwLock`; `AnonVma`/`FileRmap` hold ZERO back-
reference to `Vma` (only `Weak<AddressSpace>` + ranges, no `unsafe`, no
`Drop`); `uffd` has zero `UffdContext` implementers anywhere — always
`None`, dead code; `VmaTree`'s `BTreeMap<_, Vma>` ownership is sound (no
unsafe, no reference held across mutation, fork clones independent `Vma`
values). mm-vmm is now exhaustively cleared for this crash. Non-memory-
safety side-finding: `mergeable_with_next` (`vma.rs:427-454`) never checks
`anon_vma` equality before merging — correctness gap, not corruption,
worth a separate small fix.

### Crash #3 (guard added, C179 merged): kalloc dealloc-size mismatch in zram
`alloc_size=16384 dealloc_size=32` traced to `discard_slot` dropping
`Slot::Writeback.data: Box<Slot>` — a `Box<Slot>` drop always deallocs
`Layout::new::<Slot>()` (~32B) by construction, so the mismatch means the
pointer itself was wrong (pointed at a live 16384B `Vec<u8>`, likely
`io.rs`'s `PreparedSlot::Raw`). Zero unsafe code anywhere on
`Slot::Writeback` (one construction site, plain `Box::new`) — driver logic
cleared. Guard: plausibility check at the `free_slot_storage` choke point,
boot-verified silent across 2 boots.

### Crash #1 (FIXED, B1338 merged): `#GP` in FPU-restore during ctxsw
Root cause: `ptrace_fpu.rs`'s `set_fpregs`/`get_fpregs` had zero check that
the caller is the tracer or the target is stopped — any task could
`PTRACE_SETFPREGS` any pid, racing the target's own `fpu_save`/
`fpu_restore` on the unlocked `fpu_state` cell, tearing its XSAVE image.
Fixed: both now require `traced_by == caller` AND `state() == Stopped`.
Note: `GETREGS`/`SETREGS`/`POKEUSER` in `101_ptrace.rs` have the identical
gap — lower priority (don't race hardware-state save/restore), follow-up.

### Crash #2 (guard added, C177 merged): `#PF` cr2=0x8 in `Arc<Dentry>::drop_slow`
`Dentry.sb: Weak<SuperBlock>` held raw `0` instead of `Weak::new()`'s real
sentinel (`usize::MAX`, confirmed empirically) or a valid pointer. Guard:
always-on check in `Dentry::drop` before field-drop, boot-verified silent.

### C176 (merged): kalloc `try_merge` diagnostic gap, closed
Was gated `debug-heappoison`-only unlike siblings; widened to match. Also
proved `add_region`/`add_free_region`/`owns_range` have no internal logic
bug (a fresh region's range is mathematically guaranteed to pass its own
check immediately after insertion).

### Established, still true (condensed)
Non-determinism reconfirmed every round (need 3-5+ samples). `#UD` Arc-
clone refcount-overflow abort in `dcache` (2 call sites): a `Dentry`'s
`ArcInner.strong` corrupted before Rust's overflow guard trapped; `vfs/src`
has zero raw Arc manipulation, external. One sample = genuine OOM (zram
`disksize` scales to ~RAM, not fixable by more VM RAM). Decoded-string lead
(`HoleHdr.size` → `"hreshold"`, `recompress.rs:28`'s `"threshold"` match
arm, every copy path ruled out). Ruled out as sources: io_uring, futex
FUTEX_WAKE_OP, spawn.rs, zombies.rs/poll_subs.rs, zsmalloc. B1333/B1336
(merged): real ctxsw register-clobber fixes, not root cause. B1334/B1335
(merged): rmap TOCTOU (dead code), process_vm foreign-AS UAF (unconfirmed).

### Fast-repro recipe
```
mcp__qemu__qemu_start(arch=x86_64, features="debug-boot,debug-dealloc-diag", smp=1, paused=false)
mcp__qemu__qemu_continue(...)   # times out at 120s (no breakpoint set), boot continues regardless
# wait ~60-90s, then qemu_serial() -> often exceeds tool token cap, saved to a
# file; grep/python-search that file for FAULT/PANIC/KALLOC/corrupt-, don't Read whole
```
`addr2line -Cfi -e <elf> <rip>` + `objdump -d --start-address=...
--stop-address=...` around the faulting `rip` found every lead every round.
Decode suspicious `[KALLOC]` values as little-endian ASCII AND check for
round power-of-two/systems constants (this round's 4GiB find) first.
`debug-heappoison` = same repro but ~500s — vetoed for iteration.
`qemu_list`/`qemu_stop` stale instances first; a 120s `qemu_continue`
timeout with no breakpoint set is expected, not a hang.

### TRIED THIS ROUND, FAILED: `qemu_break`/`qemu_watch` on kernel VAs
Attempted to break at `vfs::dentry::Dentry::new` (`*0xffffffff805e3850`) to
grab a live instance and watch its `d_op` field. **Consistently fails**:
`Cannot insert breakpoint 1. Cannot access memory at address
0xffffffff805e3850` — reproduced twice, once starting paused-at-entry
(expected per tool docs: too early, kernel not paged in) and once after
letting the kernel run unpaused for 65s+ (should have been long past
paging setup — same failure anyway). This is a HIGHER-HALF kernel VA;
GDB's breakpoint insertion (writing an `INT3` byte) apparently can't
resolve it via this bridge regardless of boot stage. **Do not retry this
exact approach** — matches project memory's existing warning that the
qemu GDB bridge is unreliable for live breakpoint/watchpoint work in this
environment; stick to serial/klog forensics (this hunt's actual proven
method every round) instead.

### First command next session
1. Crash #4 (`Vma` drop): mm-vmm fully cleared — either add a guard
   covering all 4 fields, or look for corruption sources entirely outside
   mm-vmm now that the subsystem itself is ruled out.
2. Re-run the fast repro 3-5x — C177/C179 guards are live; either may
   catch the corruption directly this time.
3. Chase the 4GiB `d_op` / `kalloc_grow` size-computation lead via static
   read-through of the call chain (asm causes ruled out; live watchpoint
   ruled out as impractical) — the remaining productive angle.
