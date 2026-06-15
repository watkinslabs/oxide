# state.md — session handoff

## Headline
Building **oxide-libc**: our own glibc-ABI C library in Rust, replacing musl
(user directive 2026-06-14). Spec: `docs/59`. Crates: `crates/user/glibc`
(libc) + `crates/user/ldso` (the dynamic linker, new in G12a).
Driven by a self-paced `/loop` grinding the `docs/59§6` G0–G19 ladder, one
sub-phase per PR. **Don't stop until ladder complete or hard blocker.**

## Position
G0–G11 COMPLETE (libc core: entry, syscalls, string/ctype, malloc, stdio,
stdlib, posix, signal, time, pthread). Now in **G12 — the dynamic linker (rtld)**,
the largest sub-phase, split into its own ladder G12a–G12g.

## Merged recently
- G9b #1861 — sigaction + rt_sigreturn restorer (verified)
- G10a/b #1862/#1863 — time clocks + calendar + strftime (oracle)
- G11a #1864 — pthread create/join (clone trampoline + CHILD_CLEARTID futex + per-arch TCB/CLONE_SETTLS)
- G11b #1865 — pthread_mutex (40B, 3-state futex lock, NORMAL/RECURSIVE/ERRORCHECK)
- G11c #1866 — pthread cond(48B)/rwlock(56B)/once(4B)/TLS-keys + **main-thread TCB**
  (`init_main_tcb`: arch_prctl ARCH_SET_FS / tpidr_el0 from __libc_start_main, so
  pthread_self/keys work pre-create; Tcb gained keys[128], start is Option<StartFn>)
- G12a (this) — ldso crate skeleton + self-relocation bootstrap (`dynamic.rs`
  _DYNAMIC parse, `reloc.rs` R_*_RELATIVE self-reloc — real apply tested against an
  in-process image buffer, `syscall.rs` standalone rtld syscalls)

## G12 ladder (the rtld — docs/59§5, docs/31)
- G12a ✓ #1867 self-reloc bootstrap + crate skeleton (dynamic.rs/reloc.rs/syscall.rs)
- G12b ✓ #1868 library lookup (search.rs paths + cache.rs ld.so.cache + fs syscalls)
- G12c ✓ #1869 rtld core: bump.rs allocator (+freestanding #[global_allocator]) +
  symbol.rs (SymView + GNU/sysv hash resolve via elf::hash)
- G12d ✓ RUNNABLE RTLD (#1870 linkmap, #1871 loader, #1872 relocate, #1873 entry,
  + harness PR): `xtask ldso --check` builds ld-linux-{x86-64.so.2,aarch64.so.1}
  cdylibs (rust-lld both arches) and runs a no-libc PIE through our ld on the host
  → exit 42 / "ld-ok" (x86; aarch64 run = QEMU later). KEY FIX: `.hidden _dl_start`
  in entry.rs so `_start`'s call is a direct PC-relative call, not an unrelocated
  PLT jump (that was the 0x1856-segfault). Fixture: userspace/ldso_smoke/raw_pie.c.
- G12g ✓ **DT_NEEDED libc.so.6 linking — the rtld links + runs a REAL libc-linked
  binary** (#1878 crt-split, #1879 versioned lookup, + this: objview.rs/link.rs/mem.rs).
  `xtask ldso --check` runs dyn_libc.c (strlen via JUMP_SLOT against libc.so.6) → exit 13.
  KEYS: rtld linked `-Bsymbolic` (internal refs → RELATIVE so self-reloc covers them);
  rtld has own mem.rs (memcpy/memset/memcmp/bcmp/strlen/getauxval); read WHOLE dep file
  (elf::parse validates PT_LOAD bounds vs the buffer). Remaining G12g: lazy PLT,
  relocate.rs Kind::Tls wiring (DTV + set tp).
- ~~G12e~~ done; G12h next = dlopen/dlsym/dlclose/dladdr/dlinfo.
- G12e — symbol versioning (VERSYM/VERNEED, GLIBC_2.x matching)
- G12f — TLS (static+dynamic block, DTV, __tls_get_addr, TPOFF/DTPMOD/DTPOFF) +
  **per-thread errno** (move errno into the TCB now that main+threads have one)
- G12g — DT_NEEDED libc.so.6 linking (extend _dl_main: loader::map_object +
  search::resolve + linkmap + relocate::apply + .init_array) → run a real
  libc.so.6-linked binary; + lazy PLT (_dl_runtime_resolve) + handoff polish
- G12h — dlopen/dlsym/dlclose/dladdr/dlinfo (libdl, folded into libc.so.6)
- Harness: `xtask ldso [--check]` (tools/xtask/src/ldso.rs); builds cdylibs via
  rust-lld (`-C linker-flavor=ld.lld`) — no cross-gcc needed for aarch64 link.

## How it's built/verified (per sub-phase)
- C-ABI exports `#[cfg(feature="freestanding")] #[no_mangle] pub unsafe extern "C"`
  over always-built `pub(crate)` inner impls so the hosted oracle/tests can run.
- glibc gate: `cargo test -p glibc`, clippy default+`--features freestanding` for
  BOTH `-gnu` targets, `cargo run -q -p spec-lint | grep glibc`,
  `cargo run -q -p xtask -- glibc --check` (builds both staticlibs + runs smoke).
- ldso gate: `cargo test -p ldso`, same clippy matrix, spec-lint.
- spec-lint: `# C:` on every `pub fn`/`pub(crate) fn`/`pub const fn`; `// SAFETY:`
  ≥30 chars within 4 lines before each `unsafe {}`; one unsafe block per test body.
- Push with `SKIP_SMOKE=1` (glibc/ldso not yet wired into the boot image).

## Next task (first command)
Continue the loop at **G12e — symbol versioning** (VERSYM/VERNEED, GLIBC_2.x).
glibc binaries reference versioned symbols (printf@GLIBC_2.2.5); the rtld must
match the requested version when resolving. Add `version.rs`: parse DT_VERSYM
(u16/sym) + DT_VERNEED/DT_VERNEEDNUM (Elf64_Verneed + Vernaux chains, version
name strings); extend symbol::resolve / linkmap::lookup_global to filter by
version (hidden vs default, version index match). Pure parsing → hosted-tested
with a synthetic version table. Then wire into the freestanding resolver.
After G12e: G12f TLS + per-thread errno; G12g DT_NEEDED libc.so.6 linking +
lazy PLT (run a real libc-linked binary through `xtask ldso --check`); G12h dlopen.

## Notes
- musl path stays buildable until G19. 59 is DRAFT — edit directly (no R-block).
- Remaining after G12: G13 net, G14 nss, G15 math, G16 locale(+TZ), G17 crypt/rt/
  termios/setjmp, G18 folded-lib stubs + sysroot, G19 migrate userspace→glibc.
- Tracked follow-ups: stdio buffering+putc/getc macros, exact float dtoa, getopt
  GNU permutation, strptime, glob multi-component, IFUNC SIMD string variants
  (post-rtld, needs IRELATIVE), TLS-key destructor invocation at thread exit.
