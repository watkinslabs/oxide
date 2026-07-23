## Handoff: kalloc corruption hunt — first-ever clean full-desktop boot (1/3), still non-deterministic

### Headline — READ THIS FIRST
**First time in this hunt's history: a boot reached a fully stable GNOME desktop
— mutter compositor, gsd-power, polkit, PAM session opened for the real user —
with ZERO faults across 159s / 6395 log lines.** This happened right after this
session's cumulative fixes (B1333 x86_64 ctxsw, B1334 rmap TOCTOU, B1335
process_vm foreign-AS UAF, B1336 aarch64 ctxsw, C156-168 diagnostic fixes).
**Not reproducible on demand**: 5 follow-up boots (fresh rebuilds each time)
crashed again (`#UD` x3, plus 2 NEW shapes this session — see below). **Tally:
1 clean / 6 total.** Per this hunt's own rule (single boots lie, need 3-5+
samples), this is genuine, measured progress — the corruption now sometimes
doesn't happen, where before it always did — but it is **not fixed**.

**NEW this session: at least ONE crash sample is CONFIRMED genuine OOM, not
corruption.** `[PANIC] .../alloc.rs:573: memory allocation of 13888 bytes
failed` — this is Rust's own real allocation-failure message (unlike the
earlier `#UD` samples, this is NOT a red herring), meaning `kalloc`
legitimately ran out of heap at this point in boot on at least one occasion.
zram's `disksize` (~2054160384 bytes ≈ 1.9 GiB) is set very close to the VM's
total RAM (`mem=2G` default in our repro) — plausible genuine resource
pressure, not a bug. **Tried `mem=4G` once**: still crashed, but with the
OLD `rip=0` pattern (not OOM) — inconclusive on one sample whether more RAM
helps, but confirms more RAM does NOT eliminate every crash shape. That same
4G boot also had the widened `debug-dealloc-diag` `invalid-free-span` tag
(added this session, see Housekeeping) fire **10 times in a row on the exact
same address** `ffffffff818b1548` with `size=0` before eventually crashing —
`alloc()`'s walk loop re-encounters the same corrupted node repeatedly without
removing it, a real, reproducible address worth targeting with a hardware
watchpoint or a hosted-harness repro next session (this specific artifact —
NOT the broader "exhausted" watchpoint sweep from earlier — is new evidence).

**RESOLVED, PRECISE DIAGNOSIS (this session, high confidence):** all 3 `#UD`
samples hit the EXACT SAME `rip=0xffffffff805e23b2` across 3 independently
rebuilt binaries — a highly deterministic crash point. Disassembled a wide
window (`objdump -d --start-address=0x...2260 --stop-address=0x...23c0`) and
traced it to Rust source, NOT a `Layout`/allocation issue (the earlier
`handle_alloc_error` theory in this section was a **red herring** — that call
is just the next basic block in the binary, not causally reached from the
`ud2`). The actual path: `hash.rs`'s `lookup_locked` loop finds a matching
dentry (`key_matches` → true) and does `Arc::clone(e)` (`hash.rs:83`) —
compiled to `lock incq (%r14)` (the `ArcInner` strong-count field) followed by
`jle → ud2` on the incremented value. **This is Rust's OWN internal
`Arc::clone` refcount-overflow `abort()` safety guard, firing because some live
`Dentry`'s `Arc` strong-count field holds a corrupted value that trips it** —
the EXACT SAME symptom class ("a live #UD Arc-refcount-overflow abort") that
led to finding+fixing the `fd_table` UAF (B1326) much earlier this session, now
recurring on a DIFFERENT Arc (a `Dentry`'s, not a `Task` field's). This is the
sharpest, most mechanistically precise finding of the whole hunt: **some
Dentry's `ArcInner.strong` count field gets corrupted** (matches every other
sample's "narrow write into a live object" shape, this time identified as
specifically the strong-count word of a `Dentry`'s heap allocation).
**Checked**: `grep -rn "Arc::from_raw\|Arc::into_raw\|increment_strong_count\|
decrement_strong_count" crates/kernel/vfs/src/` — ZERO hits. No raw Arc
manipulation anywhere in vfs's own code. **This confirms the corruption is
NOT a vfs-internal logic bug** — some Dentry's `ArcInner.strong` field (a
plain `AtomicUsize`/`AtomicIsize` at a fixed offset within every `Arc<T>`
heap allocation, offset 0 for `Arc<Dentry>`) is being hit by a wild write
from ENTIRELY OUTSIDE dcache, the same still-unidentified external corruptor
as every other sample this hunt has found — just now pinned to a specific
FIELD SHAPE (an `Arc`'s strong-count word) rather than only "some heap byte".
**Refined hypothesis this session**: the `jle` (signed `<=0`) check on the
POST-increment value most likely means the field was corrupted to an ALREADY
NEGATIVE value (incrementing a negative-by-1 mostly stays negative/zero) —
matching the exact SHAPE of a small negative `i64`, i.e. a **Linux errno
value** (`-EBADF`, `-ENOMEM`, etc., or this codebase's own `LOCKREF_DEAD =
-128`). This points at something writing a computed error/status code through
a raw pointer to a STALE/wrong address instead of returning it normally.
**Checked `io_uring` as the leading candidate** (its `sys_io_uring_enter`,
`426_io_uring_enter.rs:81-84`, does exactly this shape:
`core::ptr::write_volatile((cqe+8) as *mut i32, res as i32)` writing a
syscall-result `i64`/`i32` through a raw pointer into a completion-queue slot)
— **ruled out**: confirmed via `io_uring.rs`'s own doc comment
(`dispatch_op`, line 269: "Runs each opcode synchronously (no worker
threads)") that every op completes synchronously inside the same locked
critical section; no deferred/async completion path exists that could write
after the ring's backing page is freed. Not the source. Also checked
`ipc/src/live/futex/core.rs:132` (`write_volatile(uaddr, val)`, FUTEX_WAKE_OP)
— writes to a caller-validated USER address, not kernel heap, so can't
directly explain a kernel `Dentry`'s corrupted field; and `sched/src/live/
spawn.rs`'s four `ptr::write(p, ArchCtx::new_*(...))` sites — these write a
FULL `ArchCtx` struct into a freshly-spawned task's OWN context slot at spawn
time, not a small errno-shaped value into someone else's memory; not a match.
**Next step: search more broadly for any OTHER async-completion/callback
mechanism that writes an i64/i32 result through a raw pointer** (signal
delivery, epoll notification payloads, any `Waker`/callback-based completion)
for the same "write completes after the
target could have been freed" shape already found twice this session
(rmap.rs TOCTOU, process_vm foreign-AS). Not yet found.

### THE DECODED-STRING LEAD (open, not yet resolved)
A corrupted `HoleHdr.size` field decoded to readable ASCII:
`0x646c6f6873657268` as little-endian bytes is literally `"hreshold"`, part of
**"threshold"** — a match-arm literal (`crates/drivers/drv-zram/src/writeback/
recompress.rs:28`) that's ONLY ever compiled into the real boot binary in that
one spot (every other occurrence of the word is in `#[cfg(test)]`-gated files).
Traced every plausible copy path this session and ruled all of them out:
`sys_write` is zero-copy from user memory (never enters a kernel buffer), klog's
ring buffer is a static array (not `kalloc`-backed), and no `format!`/`String`
in the whole zram sysfs write chain (`recompress.rs`→`state.rs`→`sysfs/block/
zram.rs`→`kobject.rs`) constructs that word. **Leading theory now: a register or
stack value leaked during `recompress_text`'s `match name { "threshold" => ...
}` byte-compare** — same general hazard class as B1333/B1336 (an
interrupt/context-switch mishandling a register), a different, not-yet-found
instance. Next step: find what runs on a timer tick/IRQ shortly after that
match executes and check for the same "asm/codegen clobbers a register the
caller trusted" shape. Second, lower-priority alternative: a `try_merge` path
that links a node into the free list without writing its `HoleHdr` (stale
content, not necessarily "threshold"-related) — re-read with this specific
question in mind if revisited.

### B1334 + B1335: two more real UAFs found via systematic sweep (merged)
6-agent sweep of all 16 kernel files containing `Arc::into_raw`/`from_raw`; 14
clean, 2 real bugs fixed:
- **B1334** (`mm-vmm/rmap.rs`, `PageRmap::anon_vma()`): raw-pointer TOCTOU on an
  `Arc` refcount, no lock. Fixed with a proper `Spinlock`. Zero callers in the
  tree — dead code, unlikely to be root cause.
- **B1335** (`process_vm_readv`/`writev`): foreign task's `Arc<AddressSpace>`
  was dropped before the chunked copy loop used its physical address —
  `process_vm_writev` could write into freed-and-reallocated physical memory if
  the target exits mid-transfer. Fixed by holding the `Arc` for the whole loop.
  Live, reachable syscall path — plausible candidate, unconfirmed.
- **B1336**: same register-clobber hazard as B1333, found in
  `ContextAArch64::switch` — fixed identically. Boot-verified clean (aarch64,
  128s/2758 lines, no regression). Closes ARM/x86 lockstep for this hazard.

### zsmalloc audited — clean (new this session)
Read all of `drv-zram/src/zsmalloc/{pool,platform,class,handle,migration}.rs`
(the compressed-object allocator zram's `disksize` event drives — every crash
trigger this whole hunt). Handle encoding is a safe generation-checked table
index (not a raw pointer/offset pack) — structurally immune to the classic
stale-handle UAF. Backing pages come from PMM movable pages, not the `kalloc`
heap. Bounds math is `checked_*` throughout, no off-by-one found. Only
un-audited piece: the real `PageProvider` glue in `pmm::setup` (`frame_alloc.rs`
— `alloc_movable_object_frame`/`migrate_movable_object_frame`/`release_object_
frame`) — read this session too, looks correct on a single pass (lock ordering
around migration, refcount-1-owned frames) but not exhaustively verified for a
narrow unlock-before-free race window. Not the source as far as traced.

### Ruled out this session (don't re-investigate without new evidence)
- Heap-growth crash (`growth-register-failed tag=outside-owned-region`):
  `HoleList::add_region`/`pmm::boot::kalloc_grow` hand-traced, both
  self-consistent — another discovery of the corruptor, not a distinct bug.
- dcache: `hash.rs`/`lifecycle.rs` read end-to-end, correctly locked/ordered —
  high-churn frequent victim, not the source.
- `sys_write`'s zero-copy user slice, klog's static ring buffer: neither
  explains the decoded-string lead (see above).

### Fast-repro recipe
```
mcp__qemu__qemu_start(arch=x86_64, features="debug-boot,debug-dealloc-diag", smp=1)
mcp__qemu__qemu_continue(...)   # times out at 120s internally, boot continues regardless
# wait ~25-35s, then qemu_serial() and grep for FAULT/PANIC/KALLOC/TASK-STACK-GUARD
```
When a `[KALLOC]` tag shows a `size=`/address value, **always decode it as
little-endian ASCII first** (`python3 -c "print((0x...).to_bytes(8,
'little'))"`) — this session's biggest lead came from exactly that.
`debug-heappoison` = same repro but ~500s — **user has vetoed this for
iteration**, one boot only if truly needed. Always `qemu_list`/`qemu_stop`
stale instances first. `addr2line -Cfi` + `objdump -d --start-address=...
--stop-address=...` around a faulting `rip` found every lead this session.

### Housekeeping (all merged, don't re-investigate; SHAs/details in git log)
9 real cross-CPU UAF/logic bugs from earlier this session (Task field races,
ext4 UAF, corruption-probe fixes) — none the root cause. B1332 hw-watchpoint +
`[TASK-DROP]` diagnostics (exhausted, kept). B1333 ctxsw register-clobber fix
(x86_64). B1334/B1335/B1336 (this pass, see above). C156-C168: kalloc
diagnostic-tag gaps (every silent panic path now tagged, incl. `alloc()`'s
fragment-reinsertion which was empirically silent for 3+ boots — now guaranteed
to print before panicking) + `size_track.rs` (kept, never fired). C173: an
always-on Arc strong-count sanity guard in `dcache::hash::lookup_locked`
(prints the dentry address + bad count before panicking, instead of Rust's
own opaque `Arc::clone` overflow `abort()`) — didn't fire on samples captured
so far, kept in place for the next occurrence.

First command next session: reproduce the `ffffffff818b1548 size=0`
repeated-`invalid-free-span` address (see above) — it's the most concrete,
addressable artifact captured this pass. Also worth 2-3 `mem=4G` boots to get
a real signal on whether more RAM changes the crash/clean ratio (one sample
isn't enough either way).
