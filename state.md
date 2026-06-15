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
- G12d ✓ #1870 link map (linkmap.rs: DT_NEEDED BFS dependency_order + lookup_global)
  — REMAINING G12d: the runnable-rtld milestone (see Next task)
- G12e — symbol versioning (VERSYM/VERNEED, GLIBC_2.x matching)
- G12f — TLS (static+dynamic block, DTV, __tls_get_addr, TPOFF/DTPMOD/DTPOFF) +
  **per-thread errno** (move errno into the TCB now that main+threads have one)
- G12g — lazy PLT (_dl_runtime_resolve trampoline) + .init_array order + handoff
- G12h — dlopen/dlsym/dlclose/dladdr/dlinfo (libdl, folded into libc.so.6)
- Verification gap: full dynamic run needs libc.so.6 + ld-linux built and a
  dynamically-linked binary run on the HOST kernel (same trick as the static
  `xtask glibc --check`); that harness is built as part of remaining-G12d.

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
Continue the loop at **remaining-G12d — the runnable-rtld milestone** (mostly
freestanding; verified by a NEW host harness):
1. `loader.rs` (freestanding): given a path, openat + read ehdr/phdrs, mmap each
   PT_LOAD at load_bias (first map a placeholder span for the whole image to pick
   a bias, then mmap PT_LOADs MAP_FIXED with p_flags→prot, bss zero-fill, W^X).
   Return base + parsed DynInfo + symtab/strtab/hash windows → an ObjView.
2. `relocate.rs` (freestanding): in-place full reloc applier over real mappings
   (not crate::dl's Vec buffers) — RELATIVE/GLOB_DAT/JUMP_SLOT/64/IRELATIVE/COPY,
   resolving symbols via linkmap::lookup_global. (reloc.rs already does RELATIVE.)
3. `entry.rs` + global_asm `_dl_start`/`_start`: read initial SP, compute the
   rtld's own load bias (PC-relative _DYNAMIC), call reloc::relocate_self, then
   _dl_main(sp): load the app + its DT_NEEDED graph, relocate all, run init_array,
   jump to the app entry with the original SP/auxv.
4. DYNAMIC-RUN HARNESS: extend tools/xtask — build libc.so.6 (cdylib, soname
   libc.so.6) + ld-linux-x86-64.so.2 (ldso cdylib) for both -gnu arches; compile a
   tiny dyn binary with `-Wl,--dynamic-linker=<our ld>` + `-Wl,-rpath`; run on the
   HOST kernel; assert it executes (prints + exit 0). x86 runs locally; arm = build
   + QEMU later. This is the gate that proves the rtld actually links+runs.
Split into 2-3 PRs if large (loader+reloc first, then entry+harness).

## Notes
- musl path stays buildable until G19. 59 is DRAFT — edit directly (no R-block).
- Remaining after G12: G13 net, G14 nss, G15 math, G16 locale(+TZ), G17 crypt/rt/
  termios/setjmp, G18 folded-lib stubs + sysroot, G19 migrate userspace→glibc.
- Tracked follow-ups: stdio buffering+putc/getc macros, exact float dtoa, getopt
  GNU permutation, strptime, glob multi-component, IFUNC SIMD string variants
  (post-rtld, needs IRELATIVE), TLS-key destructor invocation at thread exit.
