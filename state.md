## Handoff: kalloc/vfs/mm corruption hunt — non-deterministic, ~1 clean/16 boots

### BREAKTHROUGH this round: first-ever `merge-header-outside` data captured
C176's diagnostic-gate widening (merged) finally paid off — a boot hit the
exact path it was built to illuminate:
```
[KALLOC] seq=0 merge-header-outside node=ffffffff819b5400
  node_size=181841094446025728 bad_next=038f048e058d068c
[KALLOC] merge-trail addr=ffffffff817b7d98 size=4096
[KALLOC] merge-trail addr=ffffffff817b9d98 size=4096
[KALLOC] merge-trail addr=ffffffff817bbd98 size=10960
[KALLOC] merge-trail addr=ffffffff8194c8a0 size=64
[KALLOC] front-fragment-failed tag=outside-owned-region cur_addr=ffffffff8154c4e0 front_pad=32
```
This is the SAME crash family as the original `front-fragment-failed`
sample from the start of this hunt, now with the actual corrupted node
exposed. **Both `HoleHdr` fields are garbage together** (not just `next`) —
`node_size` decodes to nothing readable; `bad_next` as bytes is
`03 8f 04 8e 05 8d 06 8c`: even-position bytes ascend 03,04,05,06, odd-
position bytes descend 8f,8e,8d,8c — a distinct arithmetic structure, NOT
random noise, NOT ASCII text, NOT kalloc's own poison bytes (`0xEE`
data-fill / `0xA5` redzone — checked `poison.rs:29-30`, no match; this
build didn't even have `debug-heappoison` on). Both fields corrupted
together suggests a bulk/block overwrite (>=16B), not a single-pointer
stomp. Re-read `try_merge`'s actual coalesce line (`holes.rs:640-641`,
`cur.size = merged; cur.next = nxt_ref.next;`) — correct, updates both
fields together on a real merge, so this ISN'T a kalloc coalesce-logic
bug either; the corruption predates this merge attempt. **Checked and
ruled out: NOT unzeroed fresh PMM growth memory** — `node`'s address
(`ffffffff819b5400`) doesn't match any `merge-trail` entry, but `node`
was reached by walking `.next` links from previously-valid, previously-
tracked holes (the 4 `merge-trail` entries are its immediate predecessors
in the SAME walk) — i.e. this was an established, previously-good hole in
the free list, not a freshly-grown region's untouched tail (`kalloc_grow`,
`pmm/boot.rs`, does not zero pages, confirmed via read, but that can only
explain corruption in a hole nobody had validated yet, not this one).
**Pattern search done (negative result)**: searched IDT/IRQ vector alloc,
PCI capability-chain walker, generic `0..4` table-init loops, SMP/APIC ID
enum, scheduler priority tables — no match to `03 8f 04 8e 05 8d 06 8c`.
Not checked: Limine-handoff structs, ACPI/MADT, `crates/kernel/firmware/`.
Two more samples this round hit the already-known `rip=0` shape (not new)
— best next move is more samples with widened diagnostics, not more
guessing.

### Headline — READ THIS FIRST
Still not fixed. This round: merged 9 PRs — 3 real bug fixes (C176 kalloc
diagnostic-gap, B1337 hosted-test false-positive, **B1338 a genuine ptrace
FPU race that produced a live #GP crash — root-caused AND fixed, not just
diagnosed**), 2 new corruption guards (C177 `Dentry.sb`, C179 zram
`Box<Slot>`, both boot-verified silent), plus docs. Found SIX crash shapes
across FOUR different structs (`Dentry`, `Slot::Writeback`, kalloc
`HoleHdr`, `mm-vmm::Vma`) sharing the same "a pointer field inside a value
with compiler-derived `Drop` gets overwritten, then auto-drop faults
through it" shape — this pattern (B1334, C177, C179) plus the separate,
now-fixed ptrace race (B1338) account for a meaningful chunk of the
hunt's crash population, though the CORE recurring corruption (kalloc
`HoleHdr`, `Dentry` Arc strong-count) is still unexplained. Crashes
cluster near `[ZRAM-SYSFS] disksize=...` but not exclusively. Re-run the
fast repro repeatedly next session — B1338 alone may measurably shift the
clean/crash ratio since #GP-in-ctxsw was a real, recurring, INDEPENDENT
crash source, not merely a diagnosed-but-unfixed symptom.

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

### NEW crash #1 (RESOLVED into a real fix, B1338 merged): `#GP` in FPU-restore during ctxsw
`[FAULT] vec=0xd (#GP) rip=ffffffff803df8f8` → `sched::live::schedule::
switch::schedule`, disassembles to `xrstor64 (%rcx)`. `#GP` means the XSAVE
image is malformed, not unmapped. Chased the previously-noted ptrace gap to
ground: `ptrace_fpu.rs`'s `set_fpregs`/`get_fpregs` resolved ANY pid via
`resolve_user_pid` with ZERO check that the caller is the tracer or that
the target is ptrace-stopped — the SAFETY comment asserted "target parked
under ptrace" as an assumption nothing enforced. Any task could
`PTRACE_SETFPREGS` any resolvable pid, racing that target's own
context-switch `fpu_save`/`fpu_restore` on the same `fpu_state` cell
(single-mutator BY CONVENTION ONLY, no lock) — a genuine data race
producing exactly a torn XSAVE image and this `#GP`. **Fixed (B1338,
merged)**: both handlers now require `target.traced_by == caller` AND
`target.state() == TaskState::Stopped` before touching `fpu_state`,
matching Linux ptrace semantics. Boot-verified: no ptrace regressions, the
`#GP` shape has not recurred since (though non-determinism means this
isn't proof alone — watch for recurrence). **Note**: `GETREGS`/`SETREGS`/
`POKEUSER` in `101_ptrace.rs` have the identical missing-authorization
pattern (comments claim "target must be stopped", nothing enforces it) —
lower priority since they don't race a background hardware-state
save/restore the way FPU regs do, but worth a follow-up sweep.

### NEW crash #2 (RESOLVED into a guard, C177 merged): `#PF` write to cr2=0x8 in `Arc<Dentry>::drop_slow`
Disassembly showed `Dentry.sb: Weak<SuperBlock>` (offset 0x40) held raw `0`
instead of `Weak::new()`'s real sentinel (`usize::MAX`, confirmed
empirically via a throwaway hosted `rustc` test) or a valid pointer —
`lock decq 0x8(%rdi=0)` faulted. Third independent sample of a corrupted
`Dentry`-adjacent word (joins the `#UD` Arc-strong-count overflow and the
decoded-string `HoleHdr.size` lead). **Guard added (C177, merged)**: always
-on check in `Dentry::drop` before field-drop runs. Boot-verified silent
(no false positive) across 2 real boots.

### Established, still true (earlier rounds, condensed)
Non-determinism reconfirmed every round (need 3-5+ samples, single boots
lie). `#UD` Arc-clone refcount-overflow abort in `dcache` (`lookup_locked`,
`d_lookup_reval`): a `Dentry`'s `ArcInner.strong` corrupted before Rust's
overflow guard trapped; `vfs/src` has zero raw Arc manipulation, external.
One sample = genuine OOM (zram `disksize` scales to ~RAM regardless of
`mem=`, not fixable by more VM RAM). Decoded-string lead (`HoleHdr.size` →
`"hreshold"`, matches `recompress.rs:28`'s `"threshold"` match arm, every
copy path ruled out, leading theory = register/stack leak like B1333/1336
but unfound). Ruled out as corruption sources: io_uring, futex
FUTEX_WAKE_OP, sched spawn.rs, zombies.rs/poll_subs.rs, zsmalloc (all
audited clean). B1333/B1336 (merged): real ctxsw register-clobber fixes,
not the root cause. B1334/B1335 (merged): rmap TOCTOU (dead code),
process_vm foreign-AS UAF (live, unconfirmed).

### Fast-repro recipe
```
mcp__qemu__qemu_start(arch=x86_64, features="debug-boot,debug-dealloc-diag", smp=1, paused=false)
mcp__qemu__qemu_continue(...)   # times out at 120s (no breakpoint set), boot continues regardless
# wait ~60-90s, then qemu_serial() -> often exceeds tool token cap, saved to a
# file; grep/python-search that file for FAULT/PANIC/KALLOC/corrupt-, don't Read whole
```
`addr2line -Cfi -e <elf> <rip>` + `objdump -d --start-address=...
--stop-address=...` around the faulting `rip` found every lead every round.
Decode suspicious `[KALLOC]` values as little-endian ASCII first.
`debug-heappoison` = same repro but ~500s — vetoed for iteration.
`qemu_list`/`qemu_stop` stale instances first; a 120s `qemu_continue`
timeout with no breakpoint set is expected, not a hang.

### First command next session
1. Chase the breakthrough finding above FIRST: grep early-boot PCI/virtio
   enumeration code (`pci-cap ... off=` chains, msix vector assignment) and
   any other code writing small sequential/adjacent u16 values, looking for
   a match to the `03 8f 04 8e 05 8d 06 8c` byte pattern — or determine
   whether it's un-zeroed leftover physical-page content from
   `pmm::boot::kalloc_grow`'s PMM allocation (check whether PMM/buddy pages
   handed to kalloc are guaranteed zeroed before use).
2. Narrow crash #4 (`Vma` drop): mm-vmm's own field-write logic is
   confirmed clean (audited this round); collect 2-3 more samples before
   writing a guard (4 candidate fields, not enough precision yet).
3. Re-run the fast repro 3-5x sequentially — 2 guards (C177, C179) are
   live and boot-verified silent; either may catch the corruption directly.
