## B1310-kalloc-poison-lock-deadlock

### Headline
Continuing the zram/heap-corruption hunt. Still NOT fixed. This round: found and
fixed a REAL, separate, confirmed bug (a self-deadlock hazard in the heap-poison
diagnostics), captured one live UAF-write hit, then hit an unrelated environmental
blocker (`ext4 root mount ... Eio` on 3 consecutive fresh boots) before re-verifying.
`/goal` hook: "resolve all issues in handoff.md linux style no hacks no split truth"
is still active and still unmet — root cause of the original corruption is unnamed.

### This session's real fix (confirmed, not speculative)
`crates/shared/kalloc/src/poison.rs`'s `[UAF-WRITE]`/`[UAF-WRITE-SCAN]` diagnostic
prints (in `scan_window` and `quarantine`'s eviction check) used the ALLOCATING
`klog::write_raw`/`write_hex_u64`/`write_dec_u64` while the allocator's own Spinlock
was STILL HELD (these run inside `dealloc`'s locked span, before `drop(g)`). Per
`klog`'s own doc comment (`crates/shared/klog/src/lib.rs:324-325`): "Auxiliary
console sinks can allocate, so callers holding a leaf allocator lock must use
[`write_primary_raw`] rather than `write_raw`." Every OTHER diagnostic print in this
crate (`holes.rs`, `lib.rs`) already correctly uses `write_primary_*`; `poison.rs`
was the one holdout. Confirmed as the actual cause of an observed hang: a boot froze
solid (zero serial growth, GDB interrupt itself timed out) for 90+ real seconds
immediately after printing exactly one `[UAF-WRITE-SCAN]` line — the first time all
session that diagnostic branch had ever fired. Fixed by switching every call in
`poison.rs` to the `write_primary_*` route. Real, independent bug — worth keeping
regardless of the main hunt's outcome, since it was silently able to deadlock (or,
worse, on a lock that doesn't self-detect recursion, run concurrently against the
same list this diagnostic is reporting on — itself a possible corruption VECTOR,
not just a hang).

### Also added this session (`crates/shared/kalloc/src/holes.rs`)
`EvictHistory`: a ring recording (base, size, free_ip) for blocks that left the
quarantine ring and rejoined the real hole list. Lives directly on `HoleList` (not
on `poison::Quar`) specifically so `try_merge`'s own corruption print can consult it
without re-locking the allocator it's already running inside of (a real
lock-domain constraint — a naive version tried to reuse `Quar`'s lookup and would
have deadlocked the SAME way as the bug above). `try_merge`'s
`merge-header-outside` report now also emits `merge-corrupt-node-provenance
base=... freed_size=... free_ip=...` when the corrupt node matches a retained
eviction record — names "what used to live here" for a node found broken long
after the corrupting write, instead of only raw garbage bytes with no provenance.
NOT YET boot-verified against a real corruption hit (blocked by the Eio issue
below) — logic reviewed and compiles clean against the real `oxide-kernel` target.

### New evidence captured this session (live, not post-mortem)
Before the poison.rs fix was applied, one boot (`--features
debug-boot,debug-heappoison,debug-pmm`) produced, live, right at
`systemd-zram-setup@zram0.service`:
```
[72.059] [UAF-WRITE-SCAN] freed base=0xffffffff81629838 size=96 off=0 val=0x0000000000000000 free_ip=unknown
```
A ZERO-byte write at offset 0 of a still-quarantined 96-byte block — different in
character from the 3 post-mortem corruption signatures found earlier this session
(see below): this one is a genuine live catch, not a garbage-byte reconstruction.
`free_ip=unknown` because x86_64's `caller::dealloc_return_ip()` is a stub (only
aarch64 captures a real return address — see `crates/shared/kalloc/src/caller.rs`).
That gap is worth closing (a real x86_64 frame-based capture, e.g. reading the
return address off the stack at a known frame depth) since `free_ip` is otherwise
the single most direct lead to a corrupting call site this diagnostic can produce.

### Prior evidence (still valid, from before this session's boots)
3 independent boots each hit `[KALLOC] merge-header-outside` / `[PANIC] kalloc back
fragment invalid` (or `kalloc invalid free`) once zram-setup starts. Corrupted node
address and garbage pattern differ every boot (moving victim, not a fixed bad
instruction). Boot 3's raw header bytes were `FF FF FF FF EE EE EE EE EE EE EE EE
EE EE EE EE` — full quarantine poison (`0xEE`) intact except the first 4 bytes,
suggesting a 32-bit-wide write landing on an already-evicted block. Checked (via a
throwaway hosted `rustc` snippet using `core::mem::offset_of!`) whether any small
Arc'd/Box'd struct with a leading `AtomicU32` matches: `Mountpoint::m_count`
(`vfs/src/mntns.rs`) is actually at offset 8, not 0 — ruled out as a match for that
specific byte pattern. `PageRmap::mapcount` (`mm-vmm/src/rmap.rs`) lives embedded in
a static per-PFN table, never individually kalloc'd — also ruled out. No confirmed
match yet for "which struct, which call site" from static analysis alone; Rust's
`repr(Rust)` field reordering makes source-declaration order unreliable evidence,
so guessing more candidates one at a time has poor signal-to-effort ratio.

### Environmental blocker hit this session (separate from the code bug)
3 consecutive FRESH `qemu_start` builds (each triggers a real `xtask grub` rebuild +
fresh disk images) all failed identically and early:
```
[PANIC] crates/kernel/kmain/src/kmain/rootfs.rs:29: ext4 root mount (oxide-root) failed to open: Eio
```
This is a pure block-layer I/O failure before any of this session's touched code
(kalloc/poison/holes) would run meaningfully — implicates disk-image generation or
host I/O contention from rapid back-to-back rebuild+reboot cycling, not the kernel
fix. Checked: root-x86_64.img has a valid ext4 superblock per `file`(1); no stale
`qemu-system-x86_64` processes were running. Did not chase further this session
(repo policy: no boot-per-hypothesis loops) — next session should verify a boot
succeeds cleanly BEFORE trusting any further kalloc-corruption repro attempt, and
if Eio recurs, treat it as its own bug (possibly worth a hosted/offline `e2fsck`
pass on the generated image, or throttling how many fresh `qemu_start` builds run
back-to-back).

### Already ruled out (carried forward, still holds)
Today's (2026-07-21) 194-branch merge; VMA tree (`mm-vmm/src/tree.rs`); PMM
alloc/free/rmap mechanics; sched/task lifecycle (Task is a downstream victim, not
the source); `debug-fwm` peer-mapping backstop (enabled, never fired);
kernel-image/static-heap PA overlap; FPU/XSAVE buffer sizing; `as_teardown`
(`mm-pmm/src/user_as/teardown.rs`) as the PRIMARY cause — its leaf-free path is
correct, and `debug-leak-teardown` delaying the crash is very likely a
timing/reuse-order correlation, not proof of causation (every corrupted node found
lives in the ORIGINAL static 64MiB BSS heap, which PMM/`kalloc_grow` never touches).

### Concrete next step
1. First, confirm a clean boot (no Eio) before trusting any repro attempt.
2. Once booting cleanly, re-run with `--features debug-boot,debug-heappoison,debug-pmm`
   and capture either: another live `[UAF-WRITE]`/`[UAF-WRITE-SCAN]` hit (now
   safe post-deadlock-fix), or a `merge-header-outside` panic — the latter will now
   also print `merge-corrupt-node-provenance` if the node was ever quarantined,
   which is new, real forensic data not available before this session.
3. If a live UAF-WRITE hits again with `free_ip=unknown`, that's the signal to
   invest in a real x86_64 `dealloc_return_ip()` (currently a stub) — likely the
   highest-leverage remaining diagnostic gap.
4. Do NOT re-open `as_teardown`/PMM as the primary suspect without new evidence
   that contradicts "every corrupted node lives in the static BSS heap, not a
   PMM-grown region."

### Housekeeping
- Kill stale `qemu-system-x86_64` before starting new boots (`ps aux | grep
  qemu-system`) — checked clean this session, wasn't the Eio cause.
- Branches this session: `B1309-kalloc-uaf-diagnostics` (merged, PR #3735 —
  validate/dump/merge-trail/periodic_validate + PMM hardening + smoke fix) and
  `B1310-kalloc-poison-lock-deadlock` (this one — poison.rs lock fix + EvictHistory).
