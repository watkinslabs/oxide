## C138-dentry-d-op-corruption-lead

### Headline — BREAKTHROUGH, still not fixed
Found the exact struct + exact field + exact corruption signature for the
zram/heap-corruption bug, via the CANONICAL `make smoke-x86` (no custom
diagnostics needed) — the strongest lead across every session on this bug so
far. Root cause (who writes it) is still unnamed. `/goal`: "resolve all issues
in handoff.md linux style no hacks no split truth" — still unmet.

### The finding
`make smoke-x86` (default build) hit a REAL #PF 2 of 3 boot attempts, always
right at `systemd-zram-setup@zram0.service`:
```
[FAULT] err=... rip=ffffffff80647fce rflags=... cr2=0000015b00000028 pf=NP-R-K
```
`rip` resolves (via `nm`/`objdump` on the freshly built ELF) to
`<Arc<vfs::dentry::Dentry>>::drop_slow+0x1e` — disassembly:
```
mov 0x60(%r13),%rax   ; rax = self.d_op            (Dentry field, ArcInner+0x10 base)
mov 0x28(%rax),%rax   ; <-- FAULTS HERE: rax = d_op.d_release
call *%rax            ; call d_op->d_release(self)  -- Linux __dentry_kill semantics
```
This is exactly `crates/kernel/vfs/src/dentry/lifecycle.rs:11`:
`if let Some(f) = self.d_op.and_then(|o| o.d_release) { f(self); }` — legitimate,
correct code, NOT the bug. Verified real field offsets with a throwaway
`core::mem::offset_of!` test (`Dentry`'s `repr(Rust)` layout is REORDERED by the
compiler — source declaration order ≠ real offsets): `d_op` sits at Dentry
offset **80** = ArcInner+0x60, exactly matching the fault. `DentryOps::d_release`
is field 6 of 10 `Option<fn>` (8B each) = offset 0x28 within `DentryOps`,
matching the second load.

`cr2=0x15b00000028` means `self.d_op = 0x15b00000000` exactly: upper 32 bits =
`0x15b`, lower 32 bits = **0**. This is corrupted memory in a still-LIVE
`Dentry` (not a freed hole) — something wrote a 32-bit value into the UPPER
half of the 8-byte `d_op: Option<&'static DentryOps>` field while the lower
half stayed at its original zero (i.e. the field was legitimately `None`
before, then a stray 4-byte write landed 4 bytes too high). **This exact
signature — a small value in the upper 32 bits, zero in the lower 32 —
also matches an earlier boot this session's `node_size=0x100000000` on a
corrupted kalloc free-list node.** Two independent victims, same corruption
shape: strongly suggests one specific stray-write mechanism (a 32-bit store
landing 4 bytes past where it should), not two unrelated bugs.

### Why this beats every prior lead
No `debug-heappoison` needed — reproduces on a plain default build via the
project's own mandatory `make smoke-x86` gate. Names an exact live struct
field (not just free-list garbage bytes), giving a concrete target for a
watchpoint or static audit, rather than a moving/anonymous victim.

### Ruled out / superseded by this finding
`PageRmap::mapcount` and `Mountpoint::m_count` (checked in a prior pass this
session, wrong field offset for the earlier 0x100000000 pattern) are no longer
the most promising candidates — `Dentry::d_op` now is. Everything previously
"ruled out" still holds (today's branch merge, VMA tree, PMM alloc/free/rmap,
sched/task lifecycle, `debug-fwm`, kernel-image overlap, FPU/XSAVE sizing,
`as_teardown` as primary cause).

### This session's other real, independent fixes (both merged, keep regardless)
- **B1309** (PR #3735): `HoleList::validate()`/`dump()`, `try_merge` merge-trail,
  `KAlloc::periodic_validate`, PMM `kalloc_grow` mapcount/mapping hardening
  asserts, a real `smoke::pmm::run` build-break fix.
- **B1310** (PR #3736): `poison.rs`'s `[UAF-WRITE]`/`[UAF-WRITE-SCAN]` reports
  used the ALLOCATING `klog::write_raw` while the allocator's own lock was
  still held — confirmed live: a boot froze solid for 90+s right after the
  first such report fired. Fixed to use `write_primary_*` (non-allocating),
  matching the convention everywhere else in the crate. Also added
  `HoleList::EvictHistory` (records freed-block provenance for
  post-mortem corruption reports) — lives on `HoleList`, not `poison::Quar`,
  specifically to avoid the same lock-reentrancy class of bug.

### Environmental note (separate, resolved by working around it)
`qemu_start`-driven fresh builds hit `ext4 root mount ... Eio` 6x in a row
after B1310 landed; ruled out as a code regression (fires before any touched
code runs) and as host resource pressure (host was idle: 55GB free, load
<1.1/48 cores). The CANONICAL `make smoke-x86` path (different image-gen code
path, retries 3x internally) worked fine and is what produced this session's
breakthrough — prefer it over the qemu MCP tool's own build path if Eio
recurs there again.

### Concrete next step
1. Static audit: find code that writes a 32-bit value to a computed address
   that could be off-by-4-bytes from a live `Dentry`'s `d_op` field (offset 80)
   or a kalloc hole header — look for `write_bytes`/raw pointer casts near
   dentry construction/mutation, and re-check anything indexing into a
   `[u32; N]`-shaped view of memory that's actually 8-byte-field-shaped.
2. Since this reproduces on a PLAIN `make smoke-x86` boot (no debug features),
   a live GDB breakpoint at `<Arc<Dentry>>::drop_slow` (resolvable address,
   confirm via `nm`) lets you inspect `r13` (the ArcInner ptr) on EVERY
   dentry drop — but corruption already happened earlier, so this only
   confirms which dentry, not who corrupted it. A real fix needs the WRITE
   site, not the read site.
3. `free_ip` is unknown on x86_64 (`caller::dealloc_return_ip()` is a stub,
   only aarch64 captures a real return address) — closing this gap would
   help name allocator-side culprits, but this NEW finding is a live-object
   corruption, not a freed-block one, so `free_ip` wouldn't help here anyway;
   what's needed is a WRITE-side capture, not a free-side one.
4. Do NOT re-open `as_teardown`/PMM without new evidence.

### Housekeeping
- Kill stale `qemu-system-x86_64` before new boots (`ps aux | grep qemu-system`).
- Branches this session: B1309 (#3735), B1310 (#3736), C136/C137 (state.md
  housekeeping, superseded by this entry), C138 (this one).
