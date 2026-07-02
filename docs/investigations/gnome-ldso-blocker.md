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
