# state.md — session handoff

## Headline
Building **oxide-libc**: our own glibc-ABI C library in Rust, replacing musl
(user directive 2026-06-14). Spec: `docs/59`. Crates: `crates/user/glibc`
(libc) + `crates/user/ldso` (the dynamic linker). Driven by a self-paced
`/loop` grinding the `docs/59§6` G0–G19 ladder, one sub-phase per PR.
**Don't stop until ladder complete or hard blocker.**

## Position
G0–G16 COMPLETE. Done:
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

`xtask glibc --check` = exit0, 113 glibc tests.

## NEXT: G17 — crypt + rt + termios + setjmp
Small modules per family under crates/user/glibc:
- crypt: SHA-256-crypt ($5$) and SHA-512-crypt ($6$) (glibc algorithm:
  base64 1000-round scheme) + crypt/crypt_r; pure transform hosted-tested vs
  known $6$ vectors / host crypt.
- rt: clock_nanosleep/clock_settime, timer_create/settime/gettime/delete,
  sem_init/wait/post/trywait/timedwait/getvalue/destroy (futex-backed),
  mq_open/send/receive/… , aio if scoped.
- termios: tcgetattr/tcsetattr/cfgetispeed/cfsetispeed/… (ioctl TCGETS/TCSETS),
  termios struct ABI-verified vs libc.
- setjmp/longjmp + sigsetjmp/siglongjmp: per-arch asm (x86_64 + aarch64) saving
  callee-saved regs + sp + return addr; jmp_buf size ABI-verified.
Then G18 folded-lib stubs (libpthread/dl/rt/m/util .so) + ld.so.cache builder +
sysroot publish, G19 migrate userspace musl→glibc + retire musl.

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
Continue the loop at **G17 — crypt/rt/termios/setjmp** (see NEXT above). Branch
`P28-63-glibc-g17a-*` (pick the first family, e.g. crypt).

## Notes
- musl path stays buildable until G19. 59 is DRAFT — edit directly (no R-block).
- P28 prefix is the loop's ad-hoc glibc sequence; not tracked in
  metadata/index.md. Last used P28-62. C-type counter next=91. D-type next=98.
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
