# state.md — session handoff

## Headline
Building **oxide-libc**: our own glibc-ABI C library in Rust, replacing musl
(user directive 2026-06-14). Spec: `docs/59`. Crates: `crates/user/glibc`
(libc) + `crates/user/ldso` (the dynamic linker). Driven by a self-paced
`/loop` grinding the `docs/59§6` G0–G19 ladder, one sub-phase per PR.
**Don't stop until ladder complete or hard blocker.**

## Position
G0–G18 COMPLETE. Done:
- libc core G0–G11 (string/stdlib/stdio/malloc/time/signal/pthread).
- G12 dynamic linker (a–h): self-reloc, lib-search, bump alloc, symbol +
  GNU/sysv hash, symbol versioning, loader, relocate, static/IE TLS, dlopen.
  `xtask ldso --check` = 4 host smokes (raw_pie 42 / dyn_libc 13 / tls_pie 7 /
  dlopen_pie 99).
- G13 net (inet/socket/getaddrinfo), G14 nss (getpw*/getgr* files backend).
- G15 math: full libm (basic/sqrt/exp/log/pow/trig/atrig/hyper/cbrt/hypot/
  inv-hyper) — all oracle-tested vs host libm ≤2–4 ULP.
- G16 locale group (all merged):
  - G16a setlocale/localeconv/nl_langinfo (#1896)
  - G16b locale/wchar: UTF-8 mb⇄wc codec (mbrtowc/wcrtomb/mbstowcs/… +
    mbstate_t 8B) (#1897)
  - G16c locale/wctype: classify(cp)->u64 mask, 12× isw*, towupper/towlower,
    wctype/iswctype/wctrans/towctrans (#1900)
  - G16d locale/iconv: pure per-charset decode/encode over u32 pivot; UTF-8/
    16/32 LE+BE, UCS-2/4, LATIN1, ASCII; E2BIG/EILSEQ/EINVAL + TRANSLIT/IGNORE;
    iconv_open/iconv/iconv_close (#1901)
  - G16e time/tz: TZif v1/v2/v3 parse (prefers v2 64-bit block) + offset_at;
    tzset/localtime/localtime_r/mktime zone-aware; tzname/timezone/daylight
    (#1902)
- Cleared all 65 spec-lint debt entries in math/net/pthread (#1898) — glibc
  spec-lint EMPTY and kept that way each PR.
- G17 group (all merged):
  - G17a crypt: $5$ sha256crypt / $6$ sha512crypt (pure cores in workspace
    `crypt` crate, aliased libcrypt; Drepper-vector-verified) + crypt/crypt_r
    (#1904)
  - G17b rt: clock_settime, timer_*, sem_* (futex; pure value state machine),
    mq_*; struct ABI checks (#1905)
  - G17c termios: 60B struct termios + pure cfmakeraw/cf* speed + tc* ioctl
    shims (#1906)
  - G17d setjmp/longjmp/sigsetjmp/siglongjmp: per-arch global_asm (x86_64
    runtime-validated via the static smoke; aarch64 assembles); jmp_buf ABI
    (#1907)
- G18 folded-lib + sysroot (all merged):
  - G18a folded stubs: 6 empty .so shims (libpthread/dl/rt/m/util/resolv) with
    DT_SONAME + NEEDED(libc.so.6), empty dynsym; `xtask folded --check`
    (crates/user/folded-stub) (#1909)
  - G18b ld.so.cache encoder: `ldso::cache::build_cache` (glibc new-format),
    round-trips through the rtld's `cache::lookup` reader (#1910)
  - G18c sysroot publish: `xtask sysroot --check` lays out
    target/sysroot/<triple>/{lib,etc} and validates static + dynamic
    link/run + cache resolution (#1911)

`xtask glibc --check` = exit0, 127 glibc tests; 41 ldso tests.
`xtask folded --check` / `xtask sysroot --check` PASS both arches.

## glibc VALIDATED on host — conformance harness (#1914–#1917)
`xtask glibc-test`: differential conformance harness (tools/xtask/src/
glibc_test.rs + userspace/glibc_conformance/*.c). Each C program is compiled
once, linked+run BOTH against host glibc (oracle) and our sysroot (Scrt1.o +
libc.so.6 via our ld-linux on the host), stdout+exit diffed. **73/73 programs match host glibc** (through #1954). 9 subsystem audits done (printf/scanf/strftime/strtol/strtod/ctype/env/getopt/qsort): getopt got full GNU permutation + getopt_long abbreviation; strtod got hex floats + ERANGE; env got name validation. **regex (regcomp/regexec/regfree/regerror) NOW IMPLEMENTED** — ERE+BRE via a backtracking VM (Russ Cox approach) in crates/user/glibc/src/regex/{engine,mod}.rs; byte-exact vs glibc incl capture spans + error codes. Remaining libc follow-ups: regex backreferences + POSIX longest-submatch edges; math transcendentals (erf/lgamma/tgamma/j0). NEXT MAJOR: G19 on-kernel boot (the ladder exit gate; kernel /dev/console→serial blocker tracked below). Added since 55: full wide-string
family, asctime/ctime/difftime/perror, strlcpy/strlcat/explicit_bzero/
reallocarray/getsubopt, <search.h> tsearch+lsearch+hsearch+insque/remque,
strtoimax/strtoumax/rawmemchr/strcasestr, strverscmp, strsignal, ffs family,
bzero/bcopy/memfrob; **FILE backing abstraction** (stream_{read,write,seek,
tell} choke points) → fmemopen/open_memstream/fopencookie all work. Plus 4
SUBSYSTEM AUDITS (comprehensive matrices vs glibc) that each found + fixed real
bugs: printf (%s NULL crash, %#.0f point, nan spelling, %F upper), scanf (%n),
strftime (%r/%U/%W/%V/%G/%g unimpl), strtol (0x-no-digit endptr, 0b binary
prefix). Both arches build libc.so.6 (x86 run-tested; aarch64 build-parity).
~20 real bugs/gaps caught+fixed (incl MAJOR ld-linux R_*_COPY fix — COPY source
must exclude the exe, else libc DATA symbols optind/stdout/errno/environ stay 0;
printf %ls/%lc read wchar_t* as char*; printf %a was a silent stub; %s NULL
segfault). KEEP EXPANDING + AUDITING — the harness is the verify-left engine.
The subsystem-audit pattern (full matrix vs host glibc in one .c) is the
highest-yield bug finder; apply it to remaining areas (strtod, math edges).
Arch model = glibc sysdeps/: per-arch files (setjmp/{x86_64,aarch64}.rs) gated
by cfg(target_arch), built once per target triple. Naked asm = #[unsafe(naked)]
#[no_mangle] (NOT global_asm — those get localized out of the cdylib dynsym).

## NEXT: G19 — migrate userspace musl→glibc + retire musl (FINAL rung)
G19a crt1/Scrt1.o DONE+MERGED (#1913): a normal dynamic `int main()` links (no
-nostartfiles) against the sysroot + runs through our ld-linux on the HOST.
Userspace was musl (musl-gcc static bins + /lib/ld-musl-*.so.1); migration =
build oxide bins against the glibc sysroot (cc + Scrt1.o + -l:libc.so.6 +
--dynamic-linker=/lib/ld-linux-<arch>.so.2). Vendored static-musl tools
(bash/coreutils/vim/python/rg) are self-contained statics → STAY, untouched.
Exit gate: `make smoke` both arches green on glibc.

### G19b IN PROGRESS — first glibc binary on the kernel (branch P28-71, UNCOMMITTED)
On-disk now (NOT committed; boot not yet green): tools/xtask/src/rootfs.rs
(x86: builds userspace/g19_glibc_smoke against sysroot, stages /lib/
{ld-linux-x86-64.so.2,libc.so.6,6 folded stubs}+/etc/ld.so.cache+/bin/
g19_glibc_smoke + a systemd oneshot unit), userspace/g19_glibc_smoke/*.c,
sysroot.rs (build_sysroot pub(crate)). Plus 3 DEBUG SPIKES to revert before
commit: crates/kernel/smoke/src/elf.rs (PID1 = /bin/g19_glibc_smoke override),
crates/kernel/syscalls/src/fs_access_common.rs (G19FACC klog in do_access),
crates/user/ldso/src/link.rs (G19LD write(2) stage markers in link()/load_needed).

FINDINGS (from booting the glibc smoke as PID1, KVM, via `OXIDE_QEMU_KVM=1
OXIDE_SMP=1 SMOKE_MARKER=... tools/boot-smoke.sh x86`):
- Kernel ELF loader loads our PT_INTERP=/lib/ld-linux-x86-64.so.2 binary as
  PID1; our ld-linux RUNS with NO fault/panic (self-reloc works on real kernel).
- faccessat search RESOLVES libc: G19FACC trace shows /lib64=ENOENT,
  /usr/lib64=ENOENT, **/lib/libc.so.6=FOUND** (do_access/pathresolve correct).
- ext4 read_file sees ALL staged files (G19DIAG: libc.so.6=Y ld-linux=Y smoke=Y
  cache=Y) — files present + reachable.
- BUT PID1 exits CLEAN (zombie, state Z) at nsysc=4, last-sysc=faccessat(269),
  WITHOUT reaching main (no openat of libc, no marker). No userspace marker
  (neither ld-linux's write(2) G19LD nor main's write) ever reached serial.
- ROOT CAUSE of "no marker" FOUND: userspace fd 0/1/2 = /dev/console →
  ConsoleInode::write → vt_tty (the FRAMEBUFFER/VT console), NOT the serial
  UART (/dev/ttyS0 is a separate SerialInode). So our binary's write(1/2) goes
  to the graphical console, invisible to boot-smoke's SERIAL capture. ld-linux's
  faccessat shows (kernel klog→serial) but its write(2) markers don't (→VT).
  → The binary likely runs FURTHER than the serial log suggests. ARCHITECTURAL
  QUESTION (fix Linux-correct, don't hack): on Linux /dev/console follows the
  `console=` cmdline — if boot uses console=ttyS0, /dev/console writes MUST
  reach serial. Investigate the kernel console= handling + whether /dev/console
  should multiplex VT+serial; fix the KERNEL to match Linux, then the marker
  appears. (Debug spikes were reverted; re-add the PID1-override to resume.)
- BOOT HARNESS GOTCHAS (cost hours): grub defaults to TCG — must set
  `OXIDE_QEMU_KVM=1` (else 200s+ timeouts); the DEFAULT systemd boot WEDGES in
  headless (init parks in epoll_pwait, never starts default.target wants — so a
  systemd unit won't run; rcS/oxide-smokes does NOT run under systemd);
  background boot-smoke runs flaked on SMOKE_KEEP_LOG capture + KVM contention.
  Prefer the PID1-override spike (runs the binary immediately, no systemd) +
  ONE foreground `xtask grub` headless+kvm boot captured to a file.

### Remaining after G19b
- G19c: lockstep aarch64 boot of the same glibc smoke (cross-cc for the smoke).
- G19d: migrate init/probes to glibc; remove the PID1 spike.
- G19final: retire musl-as-system-libc; `make smoke` both arches green on
  glibc; mark docs/59 COMPLETE + update CLAUDE.md status line.

## How it's built/verified (per sub-phase)
- C-ABI exports `#[cfg(feature="freestanding")] #[no_mangle] pub unsafe extern
  "C"` over always-built `pub(crate)` inner impls so hosted oracle/tests run.
- Pure logic differentially tested vs host glibc/libm (libc dev-dep or declared
  host externs). BIND host result to a local BEFORE prop_assert!. No C
  hex-float literals. `#![allow(clippy::excessive_precision/approx_constant)]`
  for numeric tables. UnsafeCell::get() is safe (no unsafe block).
- glibc gate: `cargo test -p glibc`; clippy default AND `--features
  freestanding` × {x86_64,aarch64}-unknown-linux-gnu (grep -B2 'glibc/src'
  empty); `cargo run -q -p spec-lint | grep glibc/src` empty;
  `cargo run -q -p xtask -- glibc --check` exit 0.
- spec-lint: `# C:` on every pub/pub(crate)/pub const fn; `// SAFETY:` ≥30
  chars within 4 lines before each `unsafe {}`; freestanding-only `use`
  cfg-gated.
- Branch per change incl state.md (P28-NN-glibc-*); `git commit -F -` heredocs
  (no backticks in -m); push with `SKIP_SMOKE=1` if hook triggers (glibc/ldso
  not yet wired into the boot image — though crates/user/ is outside the
  smoke-hook path).

## Next task (first command)
Continue the loop at **G19 — migrate userspace musl→glibc + retire musl** (see
NEXT above). Branch `P28-70-glibc-g19a-*`. Start by auditing how userspace is
built today (grep musl in targets/, tools/xtask/rootfs*, Makefile, vendor) and
the Scrt1.o gap; this phase ends with both arches booting to login on glibc.

## Notes
- musl path stays buildable until G19. 59 is DRAFT — edit directly (no R-block).
- P28 prefix is the loop's ad-hoc glibc sequence; not tracked in
  metadata/index.md. Last used P28-110 (regex BRE). C-type counter
  next=91. D-type next=100.
- Test crate: glibc is `#![no_std]`, std is test-gated (no prelude) — in tests
  `use alloc::vec::Vec;`; derive Debug on enums asserted with assert_eq!.
- Charset-name C-string clippy fights c_char signedness across arches — use
  byte literals + `#[allow(clippy::manual_c_str_literals)]`.
- Tracked follow-ups: bit-exact correctly-rounded sqrt; huge-arg trig
  (Payne–Hanek); dedicated f32 libm cores; long double. /etc/hosts + stub DNS
  resolver; nss _r variants/setpwent/getspnam/nsswitch. lazy PLT
  (_dl_runtime_resolve); general-dynamic DTV/__tls_get_addr. stdio
  buffering+putc/getc macros; exact float dtoa; getopt GNU permutation;
  strptime; glob multi-component; IFUNC SIMD string variants (post-rtld, needs
  IRELATIVE); TLS-key destructor invocation at thread exit.
