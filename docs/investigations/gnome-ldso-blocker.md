# GNOME boot blocker — glibc ld.so `_dl_check_map_versions` assertion

Investigation brief for a fresh reviewer. **Read top-to-bottom; the CONCLUSION
supersedes every earlier hypothesis.** Prior sessions (and the first half of this
one) assumed kernel memory corruption — that has been DISPROVEN with evidence.

## The blocker

live-gnome boots to `getty.target` + `local-fs.target` (~72 s) but never reaches
gdm/graphical. Cause: udevadm + every systemd generator exit **127**. Captured
stderr (via a `debug-atexit` writev tracer that prints fd=2 as `[DYNERR]`):

```
Inconsistency detected by ld.so: dl-version.c: 204:
_dl_check_map_versions: Assertion `needed != NULL' failed!
```

getty-generator failing → no getty/login units; udevadm failing → no device/
graphics setup → GNOME blocked.

## What `needed != NULL` means (glibc elf/dl-version.c)

```c
static struct link_map *find_needed(const char *name, struct link_map *map) {
  for (tmap = GL(dl_ns)[map->l_ns]._ns_loaded; tmap; tmap = tmap->l_next)   // ns list
     if (_dl_name_match_p(name, tmap)) return tmap;
  for (n=0; n < map->l_searchlist.r_nlist; n++)                            // own searchlist
     if (_dl_name_match_p(name, map->l_searchlist.r_list[n])) return ...;
  return NULL;   // assert fires
}
```

`find_needed(<lib>)` returns NULL for a lib that IS loaded (e.g. libgcc_s.so.1,
which the same binary's own GCC_3.0 version-check resolves fine). Nondeterministic:
same binary, some boots pass, some assert; the failing `vn_file` varies. All
failing binaries pull in `libsystemd-shared-257.13-1.fc42.so` (deep NEEDED tree:
libgcc_s, libc, libcrypt, libcrypto, libseccomp, libcap, libpam, libselinux, …).

## CONCLUSION (this session, evidence-backed): NOT kernel memory corruption

Instrumentation (all `debug-*` gated, in-tree, permanent) proved the kernel does
NOT corrupt ld.so's data:

| Detector | Result |
|---|---|
| `[LOSTWRITE]` displaced-install over a present leaf — anon/kbytes/file, ALL ranges (incl brk `0x1000_0000` + ld.so .bss `0x4003_xxxx`) | **0** |
| free-while-mapped (`[FWM]`/`[COW-LEAK]`/`[MAPNEG]`/`[REFBUG]`) | **0** |
| double-alloc (same PA to 2 distinct va/root) under `debug-noreclaim` | **0** |
| anon re-fault / re-zero (same va,root → different pa) under `noreclaim` | **0** |
| `debug-noreclaim` (leak ALL frees) | assert STILL fires → not free/reuse |

⇒ ld.so's link_map chain + strdup'd name strings are **intact in memory**. So
`find_needed → NULL` is not a lost write / corrupted pointer / corrupted string.

## Verified correct by inspection (do NOT re-audit)

- x86 fault classifier: err bit0 = P (0→NotPresent, 1→Protection) — correct.
- PT walker (`hal/src/pt_walker.rs`): `map_at_level`/`walk_or_alloc` zero new
  tables, correct indices, no sibling clobber; `unmap_at_va` clears only the leaf.
- `mprotect` (`mm-pmm/src/user_as.rs::mprotect_pages`): rewrites present leaves
  only; never clears/frees.
- Context switch (`hal-x86_64/src/context.rs`): kernel callee-saved saved/restored.
- IRQ entry/resume (`hal-x86_64/src/irq.rs`): scratch regs pushed/popped LIFO;
  callee-saved ride the Rust ABI; preempt-on-return (`oxide_irq_resched_on_exit`)
  is ABI-correct Rust — user regs preserved across `schedule()`.
- Fault handling runs **IRQ-off / serialized** (no interleave race). Anon faults
  don't sleep (no `read_at`), so they're atomic.

## Ruled out earlier (also do not re-chase)

File-page corruption (RO sections match backing) · MAPZERO (BSS-tail phantom:
victims sit exactly past the RW segment `p_filesz`) · mmap overlap / wrong load
bias (VMADUMP clean; the 64 MB anon after the exe is the intended brk
`HEAP_RESERVE`, exec/src/lib.rs:348) · fstat `(dev,ino)` dedup (consistent +
unique) · wrong link-namespace (`l_ns`; walked all `r_debug.r_next` — lib is in
ns 0) · malformed ELF (libgcc_s.so.1 valid, correct SONAME + version defs) ·
bad auxv (AT_PHDR/PHENT/PHNUM/BASE/ENTRY correct).

## MEASUREMENT CAVEAT (important for anyone re-running)

The `[LINKMAP]` chain-walker (in `syscalls/src/020_writev.rs`, on the assertion)
reads via a translate-gated `rd()`; a transiently-pageable link_map page
truncates the walk → **false `MISSING-FROM-CHAIN`**. One boot showed the "missing"
lib actually present in ns 0 while still asserting. So the "chain drops a node"
observations from mid-session are partly artifact — do not treat them as fact.
The assert is real; its exact trigger is not yet nailed.

## UPDATE 2026-07-02 (further narrowing — read before re-chasing)

New disproofs + one positive lead this session:

| Hypothesis | Verdict this session |
|---|---|
| Cross-CPU / SMP race in the fault path | **Ruled out.** Assert reproduces at **smp=1** (oneboot.sh / Makefile default `SMP=1`) — boot-verified. A single-core, IRQ-off, non-sleeping fault handler has no interleave point. |
| Short-read / `read_at` partial fill leaving a zero tail | **Not firing.** `debug-atexit` boot: `[SIZE-DESYNC]`=0, all 34 `[FILLTAIL]` are legit EOF straddles (`valid == fsize−foff` exactly), `[MAPZERO]`=known-benign BSS tail. |
| Transiently-small `size_hint`/i_size | **Not firing** (`[SIZE-DESYNC]`=0). |
| Frame reuse / stale content | Still ruled out (`debug-noreclaim` STILL asserts → every alloc fresh-zeroed). |
| Layout / ASLR variation | **N/A** — oxide has **no ASLR** (`PIE_LOAD_BIAS`/`INTERP_LOAD_BIAS` fixed consts, `exec/src/lib.rs:130,136`). Load addresses identical every boot ⇒ nondeterminism is **not** layout. |

**Positive lead (from ld.so's own `LD_DEBUG=versions,scopes,files` trace, injected in
`059_execve.rs:160` under `debug-atexit`, captured via `[DYNERR]`):** the assert is
`find_needed(vn_file) → NULL` at the **version-check** stage — `checking for version
'X' in file Y required by file libsystemd-shared`, Y a version-provider dep
(libcrypt/libmount/libselinux/libpam/libm/libgcc_s…). **Every dep is mapped**
("generating link map" for all), yet libsystemd-shared's search scope lacks one
loaded provider at check time; the **failing Y varies** boot-to-boot. ⇒ a
**link-scope / `_ns_loaded` namespace-membership** effect in the loader stage —
memory intact, objects loaded, but scope/searchlist wrong. NOT content corruption.

Nondeterminism at smp=1 + fixed layout ⇒ driven by **fault/syscall ORDERING**
(timer-preemption-scheduled interleave of the generators' fork/exec/mmap/openat
sequence), not data. Next decisive instrument: a **clean** (non-char-interleaved)
capture of the `scopes` dump, or a direct trace of `_dl_map_object_deps` /
`_ns_loaded` membership vs `l_searchlist.r_list[]` at the assert, using stable
pointers. Read glibc `_dl_map_object_deps` + `_dl_check_map_versions` against
oxide's exact openat/fstat/mmap/close ordering.

Related fix landed this session (NOT the blocker): PR #2303 — a real latent **SMP**
write-protection TOCTOU that zero-filled over File/KernelBytes backing (the exact
historical mechanism of this assert), with a deterministic repro test
(`mm-vmm/src/tests_ldso_toctou.rs`). Cannot fire at smp=1, so it does not explain
this blocker; kept as a standalone correctness fix.

## UPDATE 2026-07-02 (#2) — scope is incomplete by a VARYING amount

tid-tagged `[DYNERR t=<tid>]` tracer (`020_writev.rs`) + per-tid demux of a
fresh `debug-atexit` boot:

- **12 processes asserted in one boot**, but each after a DIFFERENT number of
  SUCCESSFUL version-checks (4, 7, 9, 22, 25, 27, …). glibc prints
  `checking for version … in file Y` only AFTER `find_needed(Y)` already
  succeeded, so `find_needed` fails at a **different verneed entry each time**.
  libsystemd-shared's verneed order is fixed ⇒ the **search scope is
  nondeterministically incomplete by a varying amount**, not one fixed missing
  lib.
- Kernel chain-walker (unreliable per the caveat, but corroborating): `_ns_loaded`
  node count **varies 16/17/18/19**; libgcc_s `in ns=0` in 20 dumps, `MISSING`
  in 4. **Zero VMA overlaps** (load bias correct).

⇒ Loader builds an **incomplete dependency scope** (`_dl_map_object_deps` /
`_ns_loaded`). At smp=1 single-threaded ld.so, the nondeterminism must enter via
**varying kernel syscall results**. **Leading suspect: `fstat`/`statx`
`(st_dev, st_ino)` feeding `_dl_map_object`'s already-loaded dedup** — if two
distinct libraries ever receive a colliding/wrong `(dev,ino)`, ld.so treats the
second as already-loaded, drops it from the scope, and `find_needed` for it
returns NULL; *which* pair collides varies → varying failure point. (The earlier
"dev/ino consistent+unique" disproof checked per-lib consistency, NOT cross-lib
collision at dedup time under this lens — re-check.)

**Next instrument:** log `(path, st_dev, st_ino, load_va, l_ns)` at each library
open/`_dl_map_object` in the failing generators; look for a `(dev,ino)` collision
across the distinct libs within ONE process, or a dep whose openat/mmap
transiently errored and was skipped. Alternative mechanisms not yet excluded:
(b) a dep openat/mmap transient failure silently skipped, (c) `_ns_loaded`
append ordering. Read glibc `_dl_map_object` (dedup by `l_ino`/`l_dev`) +
`_dl_map_object_deps`.

## Where to look next (inspection is exhausted; needs a new modality)

The bug is nondeterministic, memory-intact, and survives full kernel-path
inspection ⇒ likely an ld.so-internal interaction with something the kernel does
subtly non-Linux, OR a timing/ordering effect. Highest-value targets for fresh
eyes / a deterministic harness:

1. The **page-fault ↔ ELF-loader ↔ context-switch/preempt interaction** — not any
   single line; the diff-level changes are individually correct.
2. A **deterministic hosted harness**: drive the real `PtWalkerX86` over
   HHDM-backed fake RAM + `AddressSpace::handle_page_fault_cow_rmap` through a
   scripted ld.so-like sequence (fault → write → mprotect RELRO → refault → COW),
   asserting page content + a synthetic link-list integrity. Repro in ms, no boot.
3. Re-examine `_dl_map_object` dedup / `_dl_add_to_namespace_list` ordering under
   the exact syscall-result timing oxide produces (openat/fstat/mmap/close order).

## Diagnostics available (feature flags, off in production)

`debug-atexit` (DYNERR/[DYNERR], VMADUMP, LINKMAP walker, LD_DEBUG inject,
FILLPA/INST/FILLTAIL), `debug-watchdog` ([EXIT], [LOSTWRITE], [FWM], [REFBUG]),
`debug-noreclaim` / `debug-leak-teardown` (free-path bisect), `debug-cow`
([COW-LEAK]/[MAPNEG]), `debug-syscall` (RIP symbolize, ZAPEVICT/ZAPMUNMAP),
`debug-mount`, `debug-zerotrap`.

Boot workflow (x86):
```
cd <kernel-repo>
cargo run -q -p xtask -- kernel --arch x86_64 --profile release --features "debug-atexit debug-watchdog"
cargo run -q -p xtask -- artifacts --arch x86_64
cp target/artifacts/x86_64/kernel.elf <repo>/target/artifacts/x86_64/kernel.elf   # imagectl reads this path
cd ../oxide-images && make boot PROFILE=live-gnome ARCH=x86_64
timeout 160 bash oneboot.sh output/verifyN.log 120
```
NOTE: ~20 boots this session hit measurement-reliability limits — prefer the
deterministic harness over more boot-grinding.
