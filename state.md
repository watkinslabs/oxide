# state.md — session handoff

## Headline
Building **oxide-libc**: our own glibc-ABI C library in Rust (replacing musl),
spec `docs/59`. Crates: `crates/user/glibc` (libc) + `crates/user/ldso`
(dynamic linker). Phase: **hardening libc to be bulletproof before G19
integration** (user directive). Driver = the differential conformance harness.

## Validation engine — `xtask glibc-test`
Each `userspace/glibc_conformance/*.c` is compiled once and run BOTH against
host glibc (oracle) and our sysroot (Scrt1.o + libc.so.6 via our ld-linux on
the host kernel); stdout+exit diffed. **93/93 programs byte-exact** on
x86_64+aarch64. This is the verify-left engine — keep adding programs.

## Progress tracker (per user request)
- `glibc_done.md` — functions our libc.so.6 exports (authoritative: `nm -D`),
  harness-validated. **689 / 1298** of the upstream `glibc.md` list.
- `glibc.md` — remaining TODO (609; ~160 are complex-double-only/long-double
  variants we defer; rest are specialized clusters, see below).
- Refresh after adding exports: rebuild sysroot, `nm -D --defined-only
  target/sysroot/x86_64-*/lib/libc.so.6 | awk '{print $NF}'`, re-split the two
  files by symbol membership (python partition by name-before-`(`).

## Last batch (this session — 5 parallel sub-agents, PRs #1978-1982)
- **C99 complex math** `<complex.h>` (44: cabs/carg/creal/cimag/conj/cproj/
  cexp/clog/csqrt/cpow + trig/hyperbolic/inverse, double+`f`). ABI via
  `#[repr(C)] {f64,f64}` by value = `_Complex double` on SysV/AArch64.
- **utmp/utmpx** (23) login-record DB — struct layout host-exact (sizeof 384).
- **sched + rlimit/rusage** (18) syscall wrappers (sched_*/getrlimit/prlimit/
  getrusage/getpriority/nice). getaffinity collapses byte-count ret to 0.
- **pw/gr/shadow enumeration + `_r`** (28) over the files backend +
  getgrouplist/initgroups.
- **addmntent/adjtimex/fmtmsg/getdate** (12). +nr.rs syscall consts.

## What's solid (validated earlier this phase)
- 9 subsystem audits (printf/scanf/strftime/strtol/strtod/ctype/env/getopt/
  qsort, ~25 bugs fixed); fma/fmaf correctly-rounded; regex (ERE+BRE);
  FILE backing (fmemopen/open_memstream/fopencookie); erf/erfc, tgamma/lgamma;
  Bessel j/y; inet_aton family; wcstol/wcstod family; gettext/mntent/ftw.
- LFS `*64`; `<argz.h>`; wide-string; `<search.h>`; strverscmp; strsignal.

## Remaining clusters (the real non-complex TODO)
Specialized, larger commitments — pick per integration need:
- **aio_*** (POSIX async I/O over pthread) — whole subsystem.
- **argp_*** (GNU arg parser) + **wordexp** (shell expansion).
- **backtrace*** (needs unwinder). **obstack** (macro-heavy GNU pools).
- math **complex** done; remaining **long double** (*l) variants (80-bit x86,
  deferred bulk). misc: catgets, fts, hcreate edge, regex backreferences.

## Verify gate (every PR)
`cargo run -q -p xtask -- glibc-test` (93/93, must be prev+N, zero regress);
`cargo test -p glibc`; `cargo clippy -p glibc {,--features freestanding}` (no
new warns); `cargo run -q -p spec-lint -- all | grep -i glibc` empty. Branch
`P28-NN-*` (last merged P28-138), `SKIP_SMOKE=1` push, PR, merge, delete.

## KNOWN PRE-EXISTING RED CI (NOT glibc — main HEAD already fails these)
1. `test --hosted`: `crates/kernel/vtconsole/src/tests.rs:217` — `&buf[..got]`
   where `got` is `ReadOutcome` not `usize`; vtconsole lib-test won't compile.
2. `spec-lint`: 6 findings — `ldso/src/{bump,link,search}.rs` (missing `# C:`,
   `static mut`) + `tools/xtask/src/rootfs.rs` (1059 lines > 1000 cap).
These gate the PR CI badge but are unrelated to libc; merges proceed because
the repo already operates with main red. Fixing them is separate infra work.

## Next task (first command)
Pick next cluster (recommend aio_* or argp_*+wordexp). Add `t_<x>.c`, implement,
`cargo run -q -p xtask -- glibc-test`, refresh tracker, PR. Can fan out parallel
worktree sub-agents (one cluster each, distinct module files; orchestrator
merges + refreshes tracker centrally to avoid nr.rs/mod.rs race).

## Notes
- glibc is `#![no_std]` + alloc; std is test-only. `freestanding` feature gates
  the C-ABI surface + defines panic_impl, so in-file `#[cfg(test)]` under
  freestanding can't link — the conformance harness IS the oracle.
- `crates/arch/...` setjmp etc. are per-arch `cfg(target_arch)` files.
- 4 agent worktrees remain under `.claude/worktrees/agent-*` (the merged
  P28-134..138 branches) — GC when convenient.
