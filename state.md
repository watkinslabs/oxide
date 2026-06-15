# state.md — session handoff

## Headline
Building **oxide-libc**: our own glibc-ABI C library in Rust (replacing musl),
spec `docs/59`. Crates: `crates/user/glibc` (libc) + `crates/user/ldso`
(dynamic linker). Phase: **hardening libc to be bulletproof before G19
integration** (user directive). Driver = the differential conformance harness.

## Validation engine — `xtask glibc-test`
Each `userspace/glibc_conformance/*.c` is compiled once and run BOTH against
host glibc (oracle) and our sysroot (Scrt1.o + libc.so.6 via our ld-linux on
the host kernel); stdout+exit diffed. **88/88 programs byte-exact** on
x86_64+aarch64. This is the verify-left engine — keep adding programs.

## Progress tracker (per user request)
- `glibc_done.md` — functions our libc.so.6 exports (authoritative: `nm -D`),
  harness-validated. **585 / 1296** of the upstream `glibc.md` list.
- `glibc.md` — remaining TODO (~711; ~160 are complex/long-double variants
  we defer; the rest are specialized clusters, see below).
- Refresh after adding exports: rebuild sysroot, `nm -D --defined-only
  libc.so.6 | awk '{print $NF}'`, re-split the two files by membership.

## What's solid (validated this phase)
- **9 subsystem audits** (full matrices vs glibc): printf, scanf, strftime,
  strtol, strtod, ctype, env, getopt, qsort. ~25 real bugs fixed (printf
  %ls/%a/%s-NULL/%#.0f/nan/-nan/%F; scanf %n+scanset; strftime week/ISO/%r;
  strtol 0x/0b; strtod hex-float+ERANGE; getopt GNU permutation + long
  abbreviation; env name validation; fmod/modf/remquo NaN edges).
- **fma/fmaf** — correctly-rounded software FMA (integer mantissa), vs-host
  across 4096 triples.
- **regex** (`crates/user/glibc/src/regex/`) — ERE+BRE, regcomp/regexec/
  regfree/regerror, capture spans + error codes byte-exact (Russ Cox VM).
- **FILE backing abstraction** → fmemopen / open_memstream / fopencookie.
- **erf/erfc** (series+CF) and **tgamma/lgamma** (Lanczos g=7) — transcendentals
  to ~14-15 sig figs, conformance-diffed at %.12-13g. **gettext** (C-locale
  passthrough), **mntent** (fstab parse, tested via fmemopen), **ftw/nftw**
  (temp-tree walk), **a64l/l64a**, alphasort/versionsort.
- **Bessel** j0/j1/y0/y1/jn/yn (series + recurrence-built Hankel asymptotic,
  ≤1e-6 rel, %.6g) — the asymptotic coeffs come from a runtime recurrence, no
  transcribed constants. **inet_aton/addr/ntoa/network/makeaddr/lnaof/netof**.
  **wcstol/wcstod family** (+wcscasecmp/wcstok/wcswcs). Float-variant math
  (ceilf/fmodf/…) + logb/ilogb. stdio `_unlocked` + __uflow/__overflow.
- LFS `*64` aliases + pread/pwrite/creat; `<argz.h>` vectors; wide-string
  family; `<search.h>` (tsearch/hsearch/lsearch); strverscmp; strsignal.

## Remaining clusters (the real ~580 non-complex TODO)
Specialized, larger commitments — pick per integration need:
- **aio_*** (POSIX async I/O, over pthread) — whole subsystem.
- **argp_*** (GNU arg parser, help gen) — large; **wordexp** (shell expansion).
- **backtrace*** — needs an unwinder. **obstack** (macro-heavy GNU pools).
- **utmp/wtmp**, getpwent/getgrent enumeration, sched_*/rlimit syscall wraps.
- math **complex** (c*) + **long double** (*l) variants (deferred bulk).
- misc: addmntent, adjtime, fmtmsg, catgets, getdate,
  fts, obstack, hcreate edge, regex backreferences.

## Verify gate (every PR)
`cargo test -p glibc` (144); clippy default+freestanding × {x86_64,aarch64}
(5 baseline warnings, 0 new); `cargo run -p spec-lint | grep glibc` empty
(`# C:` needs a `///` doc-comment; `// SAFETY:` ≥30 chars within 4 lines of
each `unsafe {`); `xtask glibc -- --check` exit 0; harness all-pass. Branch
`P28-NN-*` (last P28-116), `git commit -F -`, `SKIP_SMOKE=1` push (glibc not
in boot image), PR, merge, delete branch. Pre-commit hook bans "generated"/
AI-attribution in messages.

## Next task (first command)
Continue the validation sweep: pick a remaining cluster (recommend a64l/l64a
+ alphasort + small misc as a quick batch, or commit to aio/argp). Add a
`t_<x>.c`, implement, `cargo run -q -p xtask -- glibc-test`, refresh tracker,
PR. The deferred G19 on-kernel boot (kernel /dev/console→serial blocker) is
the integration step AFTER libc is deemed strong enough.

## Notes
- glibc is `#![no_std]` + alloc; std is test-only (no hardware fma/mul_add →
  fma is hand-rolled). `f64::from_bits` is const.
- `crates/arch/...` setjmp etc. are per-arch `cfg(target_arch)` files.
- `tools/xtask/src/rootfs.rs` has uncommitted G19b WIP (do NOT commit with
  libc work).
