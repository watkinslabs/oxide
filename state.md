# state.md — session handoff

## Headline
Building **oxide-libc**: our own glibc-ABI C library in Rust, replacing musl
(user directive 2026-06-14). Spec: `docs/59`. Crates: `crates/user/glibc`
(libc) + `crates/user/ldso` (the dynamic linker). Driven by a self-paced
`/loop` grinding the `docs/59§6` G0–G19 ladder, one sub-phase per PR.
**Don't stop until ladder complete or hard blocker.**

## Position
G0–G17 COMPLETE. Done:
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

`xtask glibc --check` = exit0, 127 glibc tests.

## NEXT: G18 — folded-lib stubs + ld.so.cache + sysroot
All symbols live in libc.so.6 (the folded-libc model). G18 ships the linker-
name compatibility shims real binaries NEED in their DT_NEEDED:
- Emit empty shared objects libpthread.so.0, libdl.so.2, librt.so.1,
  libm.so.6, libutil.so.1, libresolv.so.2 — each a tiny .so with DT_SONAME set
  + DT_NEEDED on libc.so.6 (no symbols of their own). Build via xtask (rust-lld,
  both arches), like the existing ldso/glibc cdylib builds in tools/xtask.
- ld.so.cache builder: write /etc/ld.so.cache in the glibc `new format`
  (CACHEMAGIC_NEW "glibc-ld.so.cache1.1", sorted entries) so the rtld's
  cache.rs (already a reader) resolves names → paths. Pure encoder hosted-
  tested by round-tripping through cache.rs's parser.
- Publish a sysroot: lib/ld-linux-*.so + libc.so.6 + the folded stubs +
  ld.so.cache + headers, laid out so a vendor cross-build can link against it.
Then G19 migrate userspace musl→glibc + retire musl (the last rung).

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
Continue the loop at **G18 — folded-lib stubs + ld.so.cache + sysroot** (see
NEXT above). Branch `P28-67-glibc-g18a-*`. Likely xtask-heavy (emit .so shims +
cache encoder), less per-fn glibc code.

## Notes
- musl path stays buildable until G19. 59 is DRAFT — edit directly (no R-block).
- P28 prefix is the loop's ad-hoc glibc sequence; not tracked in
  metadata/index.md. Last used P28-66. C-type counter next=91. D-type next=99.
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
