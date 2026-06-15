# state.md — session handoff

## Headline
Building **oxide-libc**: our own glibc-ABI C library in Rust, replacing musl
(user directive 2026-06-14). Spec: `docs/59`. Crate: `crates/user/glibc`.
Driven by a self-paced `/loop` grinding the `docs/59§6` G0–G19 ladder, one
sub-phase per PR.

## Merged this run (branches P28-NN-glibc-*)
- G0 #1840 — spec 59 + musl→glibc R-revisions (03/07/29/29a, master-plan 27/28)
- G1 #1841 — crate skeleton, ABI infra (version maps, abi goldens, symver!)
- G2 #1842 — entry path: _start/__libc_start_main/errno/exit/write; `xtask glibc`
- G3 #1843 — per-arch syscall table (internal/nr.rs), unistd, mman, auxv canary
- G4 #1844 — string/ (mem*+str*) + ctype/ascii.rs, differential proptest oracle
- G5 #1845 — malloc/ segregated allocator + global_allocator + strdup

## How it's built/verified (per sub-phase)
- C-ABI exports `#[cfg(feature="freestanding")] #[no_mangle] pub unsafe extern "C"`,
  over always-built `pub(crate)` inner impls so the hosted oracle can test them.
- Oracle: proptest vs host glibc via `libc` dev-dep (docs/59§7).
- `cargo run -p xtask -- glibc [--check]` builds both `-gnu` staticlibs + runs the
  x86 entry smoke (`userspace/glibc_hello`). aarch64 *run* = QEMU milestone (later).
- Gates each PR: `cargo test -p glibc`, `cargo clippy -p glibc` (default AND
  `--features freestanding` for both `-gnu` targets), `cargo run -q -p spec-lint | grep glibc`.
- spec-lint gotchas: `is_pub_fn` matches `pub fn`/`pub(crate) fn`/`pub const fn` →
  use `pub(crate) unsafe fn` or add `/// # C:`. Every `unsafe {}` needs `// SAFETY:` ≥30
  chars within 4 preceding lines (one block per test body).
- Push with `SKIP_SMOKE=1` (glibc not yet wired into the boot image).

## Next task (first command)
Continue the loop at **G6 — stdio**: `FILE` (ABI layout must match glibc — record in
`abi/<arch>.toml`), fopen/fdopen/fclose/fread/fwrite, buffering, `printf`/`fprintf`/
`snprintf`/`vsnprintf` (format engine), `fputs`/`fgets`/`puts`/`putchar`/`getchar`.
Then G7 stdlib (env/exit/strtol/qsort), G8 posix (fork/exec/wait/glob), … through G19
(migrate userspace musl→glibc, retire musl).

## Notes
- musl path stays buildable until G19. 59 is DRAFT — edit directly (no R-block).
- IFUNC SIMD string variants deferred to post-rtld (G12+, needs IRELATIVE).
- aarch64-unknown-linux-gnu rustup target was added this run (needed for staticlib).
