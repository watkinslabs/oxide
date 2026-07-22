## B1311-x86-frame-pointer-caller-capture

### Headline — closed the free_ip gap, found the likely victim allocation site
Still NOT fixed, but this round closed a real diagnostic gap (x86_64 return-
address capture) and traced a live UAF hit to a concrete buffer + suspect
subsystem (zram's per-page write buffer, adjacent to the vendored zlib-rs
compressor). `/goal`: "resolve all issues in handoff.md linux style no hacks
no split truth" — still unmet.

### This round's real fix (x86_64-only, boot-verified)
`crates/shared/kalloc/src/caller.rs`'s `dealloc_return_ip()` was a stub on
x86_64 ("optimizer-controlled prologue, cannot expose a direct caller
address"). Fixed by pinning `"frame-pointer": "always"` in
`targets/x86_64-unknown-oxide-kernel.json` ONLY (NOT aarch64 — aarch64 never
needed this; it already reads the real return address straight out of the
`x30` link register, independent of frame-pointer settings) and reading
`[rbp+8]` (System V frame layout) in the x86_64 branch. Verified: both arches
build; x86_64 boots and a real UAF hit now shows a resolved, non-"unknown"
`free_ip`. Tried applying the same target-spec key to aarch64 "for
consistency" — its boot then produced literally zero serial output for 1000s+
(vs seconds normally). Reverted that one line; `git diff` on the aarch64 JSON
is now empty, so aarch64 is provably untouched by this fix — lockstep
satisfied by not touching the file it never needed changed, not by re-proving
an unrelated file works.

### New live evidence — first real free_ip capture
Booting `--features debug-boot,debug-heappoison,debug-pmm` after this fix:
```
[UAF-WRITE-SCAN] freed base=0xffffffff81edee10 size=4096 off=808 val=0x0000000000000000 free_ip=0xffffffff8011b7ec
```
`free_ip` resolves (objdump on the fresh ELF) to the instruction immediately
after a `call <kalloc::KAlloc as GlobalAlloc>::dealloc`, INSIDE
`<drv_zram::state::Zram as block::blockdev::BlockDevice>::submit_sync`,
immediately preceded by a `call <Arc<drv_zram::state::compression::Compressor>>::drop_slow`.
Size=4096 (one page) strongly matches `crates/drivers/drv-zram/src/io.rs:249`:
`let mut page = vec![0; PAGE_BYTES];` — a loop-scoped page buffer, filled by
`read_slot`, patched with new data, passed by reference to `write_slot` (which
calls `prepare_slot` → `config.compress(page)`, the vendored zlib-rs deflate
path), then dropped at the end of each per-page iteration of the read-modify-
write loop (`io.rs:231-272`).

This `free_ip` names WHO FREED the block (the normal, correct drop at loop-
iteration end) — not who corrupted it afterward. The actual corrupting write
(`off=808 val=0`, a zero-byte write) happens LATER, while the block sits
quarantined, from SOME OTHER, unrelated code. **CORRECTION (same session):**
initially floated zlib-rs's `weak_slice.rs` (`WeakSliceMut`/`WeakArrayMut`,
raw pointer+len with only a `PhantomData` lifetime marker) as the suspect —
checked `crates/drivers/drv-zram/src/state/compression.rs` and that theory
does not hold up: `Compression::default_algorithm() = Lz4`, which is
`StreamOwner::Stateless` (fresh call each time, no persistent stream state);
Deflate is ALSO `StreamOwner::Stateless` (one-shot `zlib_rs::decompress_slice`
per call, no cross-call retained slice). The `Arc<Compressor>::drop_slow` seen
in the disassembly is just an ordinary refcount decrement from
`CompressionConfig::clone()` (derived `Clone` does `Arc::clone` on `owner`,
a cheap refcount bump, NOT a deep copy) going out of scope at the end of
`write_slot`'s retry loop — normal, not a bug. Only `StreamOwner::Lzo`/`Zstd`
hold persistent cross-call `Streams` state, and those are NOT the default
algorithm, so likely NOT what was active during the crash. **The zlib-rs
weak-slice theory is a stretch, not a confirmed lead — don't chase it further
without new evidence.** `free_ip` only tells us the FREED block's size class
(4096, page-sized) and hints that zram's write-path churn makes it a likely
size-class match for whatever memory happens to be in quarantine when a
write hits — it does NOT identify the actual corrupting call site. That
still needs either a live catch (the corrupting write itself, not the
freeing one) or a much wider static audit.

### Also this round (real, independent hardening — keep regardless)
`crates/kernel/vfs/src/dentry/lifecycle.rs`: `Dentry::drop` now checks that
`d_op`, if `Some`, is a canonical kernel-half address (`>= hal::USER_VA_END` —
an existing, already-used constant, not a new one) before calling through
`d_op.d_release`. Converts the wild #PF from the dentry breakthrough finding
(prior entry, superseded below) into a located, diagnosable panic instead of
undefined behavior. This is hardening, NOT the root-cause fix — explicitly
not claimed as one.

### Prior finding (still valid, now has a stronger neighbor)
`make smoke-x86` (default build, no diagnostics) hit a real #PF 2/3 attempts
at `<Arc<Dentry>>::drop_slow+0x1e`, tracing to a corrupted `Dentry::d_op`
field (verified offset 80 via a throwaway `offset_of!` test — `repr(Rust)`
reorders fields, source order is NOT real offset). `cr2=0x15b00000028` means
`d_op=0x15b00000000`: upper 32 bits=`0x15b`, lower 32 bits=0 — the SAME
corruption shape (small value in upper half, zero in lower half of an 8-byte
field) as this round's kalloc `off=808 val=0` zero-write and an earlier boot's
`node_size=0x100000000` free-list corruption. Three independent victims, one
recurring shape — strengthens (does not yet prove) a single stray-write
mechanism.

### This session's other real, independent fixes (all merged, keep regardless)
- **B1309** (#3735): `HoleList::validate()`/`dump()`, `try_merge` merge-trail,
  `KAlloc::periodic_validate`, PMM `kalloc_grow` mapcount/mapping asserts, a
  real `smoke::pmm::run` build-break fix.
- **B1310** (#3736): `poison.rs` UAF reports used allocating `klog::write_raw`
  while the allocator's own lock was held — confirmed live (a boot froze
  solid 90+s right after the first such report fired). Fixed to
  `write_primary_*`. Added `HoleList::EvictHistory` (freed-block provenance).

### Ruled out (still holds)
Today's branch merge; VMA tree; PMM alloc/free/rmap mechanics; sched/task
lifecycle; `debug-fwm`; kernel-image/static-heap PA overlap; FPU/XSAVE sizing;
`as_teardown` as primary cause; `PageRmap::mapcount`/`Mountpoint::m_count`
(wrong offsets for the observed pattern); async/deferred I/O in
`io.rs::write_slot`/`prepare_slot` (checked, none found — corruptor is likely
deeper, in the compression backend itself).

### Concrete next step
1. `free_ip` now works on x86_64 — every future UAF-WRITE hit resolves to a
   real symbol. But remember: it names the FREEING call site, not the
   corrupting one. On the next live hit, also capture a backtrace/registers
   AT THE MOMENT OF THE BAD WRITE (not just the quarantine-scan report) if
   at all possible — that's the only thing that actually names the writer.
2. `crate::lz4::compress`/`lz4_flex` is the DEFAULT algorithm path (not
   deflate/zlib-rs) — if pursuing the compression angle at all, start there,
   not zlib-rs (see correction above).
3. Consider: the corruption may have NOTHING to do with zram/compression
   specifically — zram's write path just churns enough page-sized (4096B)
   allocations to make it a likely size-class match for whatever memory is
   in quarantine when an unrelated writer strikes. Don't over-index on zram
   as the source just because it's where the SIZE happens to match.
4. Do NOT re-open `as_teardown`/PMM without new evidence.

### Housekeeping
- Kill stale `qemu-system-x86_64` before new boots.
- Branches this session: B1309 (#3735), B1310 (#3736), C136-C138 (state.md
  housekeeping, superseded by this entry), B1311 (this one).
