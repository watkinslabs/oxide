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
- G12a ✓ self-reloc bootstrap + crate skeleton
- G12b — DT_NEEDED graph + lib search (LD_LIBRARY_PATH/ld.so.cache) + mmap PT_LOAD
- G12c — symbol resolution + full reloc set (reuse `crate::dl` engine: RELA/JMPREL/
  GLOB_DAT/JUMP_SLOT/64/IRELATIVE/COPY)
- G12d — symbol versioning (VERSYM/VERNEED, GLIBC_2.x matching)
- G12e — TLS (static+dynamic block, DTV, __tls_get_addr, TPOFF/DTPMOD/DTPOFF) +
  **per-thread errno** (move errno into the TCB now that main+threads have one)
- G12f — lazy PLT (_dl_runtime_resolve trampoline) + .init_array order + handoff
- G12g — dlopen/dlsym/dlclose/dladdr/dlinfo (libdl, folded into libc.so.6)
- Verification gap: full dynamic run needs libc.so.6 + ld-linux built and a
  dynamically-linked binary run on the HOST kernel (same trick as the static
  `xtask glibc --check`); build that dynamic-run harness around G12b/c.

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
Continue the loop at **G12b**: in `crates/user/ldso` add the freestanding loader
core — DT_NEEDED dependency walk, library search path (LD_LIBRARY_PATH, /lib64,
/lib, ld.so.cache parse), and mmap-based PT_LOAD mapping of each DSO (openat+mmap
via `syscall.rs`, extended with NR_OPENAT/NR_MMAP/NR_CLOSE/NR_READ/NR_PREAD64 +
NR_FSTAT). Hosted-test the search-path resolution + a fake ld.so.cache parse;
defer the real mmap run to the dynamic-run harness (G12c).

## Notes
- musl path stays buildable until G19. 59 is DRAFT — edit directly (no R-block).
- Remaining after G12: G13 net, G14 nss, G15 math, G16 locale(+TZ), G17 crypt/rt/
  termios/setjmp, G18 folded-lib stubs + sysroot, G19 migrate userspace→glibc.
- Tracked follow-ups: stdio buffering+putc/getc macros, exact float dtoa, getopt
  GNU permutation, strptime, glob multi-component, IFUNC SIMD string variants
  (post-rtld, needs IRELATIVE), TLS-key destructor invocation at thread exit.
