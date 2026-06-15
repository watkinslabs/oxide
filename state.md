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

## Progress tracker (per user request) — THREE files now
- `glibc_done.md` — functions libc.so.6 exports (`nm -D`), harness-validated.
  **987 / 1303**.
- `glibc.md` — achievable TODO not yet exported. **182**.
- `glibc_unsupported.md` — **132** genuinely-blocked: 122 long-double (`*l`,
  `*l` complex, strtold/wcstold, qecvt/qfcvt/qgcvt, strfroml, nexttoward*) —
  x86_64 `long double`=80-bit f80, Rust has no f80 so the extern-C ABI is
  inexpressible; + 10 `__ppc_*` (PowerPC-only, arch N/A). NOT a deferral list.
- Refresh: rebuild sysroot (the harness does it), `nm -D --defined-only
  target/sysroot/x86_64-*/lib/libc.so.6 | awk '{print $NF}'`, then the
  three-way python re-split: done=exported, unsupported=longdouble|__ppc,
  todo=rest.

## AUTONOMOUS LOOP IN PROGRESS (user: "do this in a loop, do not stop")
Land every achievable glibc function via rounds of ~6 parallel worktree
sub-agents → central integrate (merge w/ union driver on registration files,
resolve, full harness+workspace+spec-lint, refresh trackers) → repeat until
glibc.md empty. Each agent's gate = differential conformance vs host glibc.
- Round 1 (PRs #1978-1982): complex math, utmp, sched/rlimit, pw/gr enum, misc.
- Round 2 (PRs #1986-1991): obstack, rand48+random, fenv (x86+arm), netdb
  host/proto/serv/net/netgroup, syslog+err/error, wide-char stdio. 99/99.
- B127 (#1984): cleared pre-existing red CI (see below).

## What's solid (validated this phase)
- printf/scanf/strftime/strtol/strtod/ctype/env/getopt/qsort audits; fma;
  regex; FILE backing; erf/tgamma/lgamma; Bessel; inet; wcsto*; complex math;
  obstack; rand48+TYPE_3 random; fenv; netdb DBs; syslog/err; wide stdio;
  fnmatch (POSIX [:class:]/[.coll.]/[=equiv=]); LFS *64; argz; search; utmp;
  sched; pw/gr/shadow enum.

## Remaining achievable clusters (the 352 TODO) — next rounds
- aio_* (async I/O over pthread); argp_*+wordexp+argz/envz extras.
- backtrace* (frame-pointer/unwinder); fcvt/ecvt/gcvt+strfromd/f; printf_size.
- pty/tty (openpty/forkpty/ptsname/grantpt/ttyname/isatty/tcgetpgrp).
- fs+proc syscalls (mount/umount/madvise/mlock/mremap/mknod/truncate64/ioctl/
  fcntl/readv/writev/select/getrandom/getentropy/sysconf/getauxval/...).
- ucontext (getcontext/makecontext/swapcontext, per-arch asm).
- DES crypt (encrypt/setkey/ecb_crypt/cbc_crypt); catgets.
- stdio64 + GNU __f* introspection; f64/f32 math extras (exp10/llround/
  roundeven/fromfp/totalorder/nextup/sincosf/...); strptime/wcsftime/strfmon.

## Verify gate (every PR)
`cargo run -q -p xtask -- glibc-test` (93/93, must be prev+N, zero regress);
`cargo test -p glibc`; `cargo clippy -p glibc {,--features freestanding}` (no
new warns); `cargo run -q -p spec-lint -- all | grep -i glibc` empty. Branch
`P28-NN-*` (last merged P28-138), `SKIP_SMOKE=1` push, PR, merge, delete.

## CI is GREEN (B127 / PR #1984 cleared the pre-existing red)
Fixed the 5 hosted-test/spec-lint breakages that were red on main (all
unrelated to the new libc clusters, several masked behind the first compile
error): vtconsole test used `tty.read()` (now `ReadOutcome`) as a usize;
spec-lint `code/static-mut` false-positive on `&'static mut T` (ldso); 3
ldso pub fns missing `# C:`; `rootfs.rs` over the 1000-line cap (split to
`rootfs_etc::write_accounts_and_markers`); crt1 `_start` global_asm! emitted
under cfg(test) → duplicate-symbol; glibc `fnmatch` diverged from glibc on
POSIX `[.coll.]`/`[:class:]`/`[=equiv=]` sub-brackets (proptest `[![.]`) —
now parses all three + 12 char classes, proptest charset broadened.
All 6 PR checks pass (build×4, spec-lint, test --hosted).

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
