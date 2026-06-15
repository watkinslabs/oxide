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
- G6a #1846 — stdio printf format engine + write-side (printf/puts/fwrite) + FILE
- G6b #1847 — scanf engine + sscanf/vsscanf
- G6c #1848 — read-side (fopen/fread/fgets/getline/fseek) + scanf over FILE
- G7a #1849 — strtol family + qsort/bsearch + abs/div
- G7b #1850 — strtod/strtof + rand/srand (glibc TYPE_3, host-matched)
- G7c #1851 — environ/getenv/setenv/unsetenv/putenv/clearenv
- G7d #1852 — atexit/__cxa_atexit/exit-handlers + abort (G7 stdlib complete)
- G8a #1853 — posix process: fork/vfork/exec*/wait* + getuid/getpid/...
- G8b #1854 — posix fds+fs: pipe/dup + getcwd/unlink/mkdir/rename/... (via *at)
- G8c #1855 — struct stat (per-arch) + stat/fstat/lstat/fstatat
- G8d #1856 — fnmatch (oracle caught swapped PATHNAME/NOESCAPE flags)
- G8e #1857 — getopt/getopt_long (POSIX order; GNU permutation = follow-up)
- G8f #1858 — dirent: opendir/readdir/closedir via getdents64
- G8g #1859 — glob/globfree (G8 posix COMPLETE)
- G9a #1860 — signal: sigset_t (oracle caught glibc 32/33 reservation) + kill/raise/sigprocmask
- G9b #1861 — sigaction + rt_sigreturn restorer (x86 trampoline; verified) + signal() (G9 COMPLETE)
- G10a #1862 — time: clocks + gmtime/timegm/mktime (oracle calendar)
- G10b (this) — strftime (oracle vs host)

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
Continue the loop at **G11 — pthread** (the big one): READ docs/54 + docs/14 first.
Split: G11a TLS + thread create (clone CLONE_VM|FS|FILES|SIGHAND|THREAD|SETTLS|
PARENT_SETTID|CHILD_CLEARTID, mmap stack+TLS, set FS base / TPIDR, __tls_get_addr,
pthread_self/create/exit/join via CHILD_CLEARTID futex); G11b mutex
(pthread_mutex_t 40/48B, futex); G11c cond/rwlock/once/keys. Smoke each on host.
Remaining ladder: G12 ldso (rtld), G13 net, G14 nss, G15 math, G16 locale (+TZ),
G17 crypt/rt/termios/setjmp, G18 folded-lib stubs + sysroot, G19 migrate userspace
musl→glibc + retire musl. Tracked follow-ups: stdio buffering+putc/getc macros,
exact float dtoa, getopt GNU permutation, strptime, glob multi-component, IFUNC
SIMD string variants (post-rtld).

## Notes
- musl path stays buildable until G19. 59 is DRAFT — edit directly (no R-block).
- IFUNC SIMD string variants deferred to post-rtld (G12+, needs IRELATIVE).
- aarch64-unknown-linux-gnu rustup target was added this run (needed for staticlib).
