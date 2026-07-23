## Handoff: kalloc corruption hunt — first-ever clean full-desktop boot (1/3), still non-deterministic

### Headline — READ THIS FIRST
**First time in this hunt's history: a boot reached a fully stable GNOME desktop
— mutter compositor, gsd-power, polkit, PAM session opened for the real user —
with ZERO faults across 159s / 6395 log lines.** This happened right after this
session's cumulative fixes (B1333 x86_64 ctxsw, B1334 rmap TOCTOU, B1335
process_vm foreign-AS UAF, B1336 aarch64 ctxsw, C156-168 diagnostic fixes).
**Not reproducible on demand**: 2 immediate follow-up boots on the IDENTICAL
build both crashed again (`#UD` invalid-opcode x2). **Tally: 1 clean / 3
total.** Per this hunt's own rule (single boots lie, need 3-5+ samples), this
is genuine, measured progress — the corruption now sometimes doesn't happen,
where before it always did — but it is **not fixed**.

**Both `#UD` samples resolved this session — both land in/adjacent to
`vfs::dcache::alloc::d_lookup_reval`, the fourth distinct crash this whole
session in or near that exact function** (2x earlier `drop_slow` NULL-Arc-decref
samples were dcache-adjacent too, plus one `malformed-free-size` sample right
after dcache/`TASK-DROP` activity — this is now well beyond "high-churn
coincidence", `d_lookup_reval` specifically is the single most recurring site).
Disassembly at the fault (`objdump -d`) shows the trapping `ud2` sitting
IMMEDIATELY adjacent to a `call handle_alloc_error` — the standard Rust codegen
for an allocation-`Layout` size/align overflow panic, not a raw "jumped into
garbage" symptom. **`rdi=0x86` at fault time matches EXACTLY across both
independent samples** (different boots) — strong evidence this is a
deterministic code path (same inputs, same intermediate values every run) that
trips over corrupted data placed there by something else, not itself random.
**FOUND the exact mechanism, root cause still open.** `d_lookup_reval`
(`dcache/alloc.rs:78-101`) calls `DENTRY_HASHTABLE.lookup_rcu` (`dcache/
hash.rs:96-109`), whose FIRST action is `let (s1, snap) = { let g =
b.entries.lock(); (b.seq.load(...), g.clone()) };` — cloning the bucket's
`Vec<Arc<Dentry>>`. **`DENTRY_HASHTABLE.buckets` is a fixed 256-entry `static`
array (`hash.rs:112`), NOT `kalloc` heap memory.** If a `Bucket`'s `Vec`'s
`len`/`cap` fields (which live INLINE in that static array, not in a separate
heap block) get overwritten with a garbage value by a stray write from
anywhere else in the kernel, `Vec::clone()` computes `len * size_of::<Arc<
Dentry>>()` for the new allocation's `Layout` — if that's absurd/overflowing,
`handle_alloc_error`/an overflow panic fires exactly here. **This reframes the
whole hunt: the corruptor is very likely a GENERIC wild/stale-pointer WRITE,
not something specific to kalloc's heap** — it happens to sometimes land in
kalloc-managed memory (explaining `HoleHdr`/`Task`/`InetFileOps` samples) and
sometimes in FIXED static kernel data like this hashtable (explaining the
`#UD` samples). The corruption target varies because the WRITER's target
address is wrong/stale, not because kalloc itself misbehaves differently each
time. **Next step: this doesn't point at `d_lookup_reval` as the bug — it's
another victim. Find what writes through a stale/uninitialized pointer that
could resolve to EITHER a kalloc heap address OR `DENTRY_HASHTABLE`'s static
address range** — check for any raw pointer arithmetic that's supposed to
target a heap object but could compute a wrong (small offset, uninitialized,
or freed-and-reused-as-something-else) address instead. A pointer that's
sometimes valid-heap and sometimes lands in unrelated static BSS is most
consistent with an UNINITIALIZED or ZEROED pointer being dereferenced+offset
(landing near address 0 + some small stride, or a stale physical/virtual
address translation), not a properly-typed dangling `Arc`. **Checked adjacency
(`nm`)**: `DENTRY_HASHTABLE` (`0x8069bee0`) sits ~318 KiB BEFORE
`kalloc::STATIC_HEAP` (`0x806eb000`) with other static data in between — NOT
immediately adjacent, so this ISN'T a simple "heap buffer overflow bleeds
forward into the next static struct" mechanism. Supports the wrong-pointer (not
overflow) theory above.

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
to print before panicking) + `size_track.rs` (kept, never fired).

First command next session: 5-10 `smp=1` fast-repro boots on current `main`,
tally clean-vs-crash, and for any crash resolve `rip` via `addr2line`/`objdump`
— see "Headline" above.
