## B1312-dentry-d-op-sanity-sweep

### Headline — pattern now generalized: this is a WILD write, not a buggy free site
Still NOT fixed. This round's evidence closes off the "one buggy subsystem"
framing entirely: TWO independent, unrelated, perfectly ordinary free sites
(zram's page buffer, ext4's read buffer) both got named as "who freed the
block later found corrupted" — neither is a bug. The corruptor is a WILD
write from somewhere else, landing on whatever memory happens to be
quarantined/live at the time, not a bug in whichever subsystem happens to
own that memory. `/goal`: "resolve all issues in handoff.md linux style no
hacks no split truth" — still unmet.

### New evidence this round
Added `vfs::dcache::debug_scan_d_op_sanity()` (`crates/kernel/vfs/src/dcache/hash.rs`,
gated `debug-heappoison`): walks all 256 dentry-hash buckets, checks every
LIVE dentry's `d_op` for the same canonical-address violation as the
`Dentry::drop` hardening check, wired into the same per-execve checkpoint as
kalloc's `validate_global()`. Purpose: catch a live-object corruption (the
`Dentry::d_op` class) while the dentry is still alive, not only when its
refcount happens to hit zero. Both arches build; x86_64 boot-verified.

That SAME boot instead hit a `kalloc back fragment invalid` panic, and this
time `EvictHistory` (added last session, never fired with real data before)
finally reported real provenance:
```
[KALLOC] merge-corrupt-node-provenance base=ffffffff81a14970 freed_size=192 free_ip=0xffffffff80133483
```
`free_ip` resolves to the instruction after `call ...::dealloc` inside
`ext4::mount::io::read_byte_range` (`crates/kernel/ext4/src/mount/io.rs:61-65`):
a `Vec<u8>` read-request buffer (`BlockRequest::buffer`), freed completely
normally when `req` goes out of scope at the end of the function, after its
needed slice was already copied into the real return value. Nothing wrong
with this code.

**Put together with last round's zram finding**: two totally unrelated
subsystems (zram's compression write path, ext4's block-read path), both
producing textbook-ordinary `Vec<u8>` frees, have now both been named by
`free_ip` as "the block later found corrupted used to belong to me". Neither
free site is buggy. The only thing they share is being frequent, page/sub-
page-sized heap churn during boot — i.e. likely victims BECAUSE they are
common allocation sizes at a busy time, not because either's code is wrong.
**Conclusion: stop looking for "which subsystem's free is buggy" — the write
itself is coming from somewhere unrelated to whatever it lands on.**

### This round's other real, working diagnostic (keep, proven live)
`EvictHistory` (`HoleList`, added B1310) is now PROVEN to work end-to-end: it
sat unused/unfired for an entire session, then on this exact boot produced
real, correct, resolvable provenance the moment a corruption hit a
previously-evicted block. Worth keeping and trusting for the next hit.

### Ruled out this round
Zram's compression backends as the corruptor (checked in the prior
correction — default algorithm is stateless; not re-litigating). Any
single-subsystem "buggy free" framing at all — see conclusion above.

### Everything still ruled out from prior rounds
Today's branch merge; VMA tree; PMM alloc/free/rmap mechanics; sched/task
lifecycle; `debug-fwm`; kernel-image/static-heap PA overlap; FPU/XSAVE sizing;
`as_teardown` as primary cause; `PageRmap::mapcount`/`Mountpoint::m_count`.

### This session's real, independent fixes (all merged, keep regardless)
- **B1309** (#3735): `HoleList::validate()`/`dump()`, `try_merge` merge-trail,
  `KAlloc::periodic_validate`, PMM `kalloc_grow` hardening asserts, a real
  `smoke::pmm::run` build-break fix.
- **B1310** (#3736): fixed a confirmed self-deadlock in `poison.rs` (allocating
  `klog` calls under the allocator's own lock). Added `HoleList::EvictHistory`
  — proven working this round (see above).
- **B1311** (#3740): real x86_64 `free_ip` capture (`frame-pointer=always`,
  x86_64-only — see that PR for why aarch64 was excluded). `Dentry::drop`
  d_op sanity hardening.
- **B1312** (this one): dcache-wide periodic `d_op` sanity sweep.

### Concrete next step
1. Since the writer is unrelated to whatever it lands on, static "read the
   code near the victim" audits (zram, ext4, dentries) are a dead end —
   already tried 3x, 3 different unrelated innocent victims. STOP that
   approach.
2. The only ways left to actually name the writer: (a) a hardware watchpoint
   on a specific address (tooling doesn't support this — checked `qemu_break`/
   `qemu_info`, no watch capability exposed) or (b) a much broader, address-
   space-wide instrumentation approach — e.g. periodically re-verifying poison
   on ALL quarantined blocks at a MUCH tighter interval than the current
   `scan_window(q, 128)` sweep (`poison.rs`), to shrink the corruption-to-
   detection window enough that "what ran in between" becomes a short,
   examinable list (e.g. via a serial trace of syscall entry/exit) rather
   than an entire boot phase.
3. Given 3 wild, unrelated victims (zram Vec, ext4 Vec, live Dentry) — this
   smells like a single dangling/uninitialized RAW POINTER somewhere that
   gets written through unconditionally regardless of what it points to.
   Grep for raw pointer fields (not `Arc`/`Box`/`&`) stored long-term in a
   struct (not a local) — those are the ones that can go stale across a
   realloc/free without the compiler catching it. Haven't done this sweep
   yet.
4. Do NOT re-open `as_teardown`/PMM without new evidence.

### Housekeeping
- Kill stale `qemu-system-x86_64` before new boots.
- Branches this session: B1309 (#3735), B1310 (#3736), B1311 (#3740),
  C136-C139 (state.md housekeeping, superseded), B1312 (this one).
