# state.md — session handoff

## Headline
Building **oxide-libc**: our own glibc-ABI C library in Rust, replacing musl
(user directive 2026-06-14). Spec: `docs/59`. Crates: `crates/user/glibc`
(libc) + `crates/user/ldso` (the dynamic linker). Driven by a self-paced
`/loop` grinding the `docs/59§6` G0–G19 ladder, one sub-phase per PR.
**Don't stop until ladder complete or hard blocker.**

## Position
G0–G15 COMPLETE + G16a/G16b. Done:
- libc core G0–G11 (string/stdlib/stdio/malloc/time/signal/pthread).
- G12 dynamic linker (a–h): self-reloc, lib-search, bump alloc, symbol +
  GNU/sysv hash, symbol versioning, loader, relocate, static/IE TLS, dlopen.
  `xtask ldso --check` = 4 host smokes (raw_pie 42 / dyn_libc 13 / tls_pie 7 /
  dlopen_pie 99).
- G13 net (inet/socket/getaddrinfo), G14 nss (getpw*/getgr* files backend).
- G15 math: full libm (basic/sqrt/exp/log/pow/trig/atrig/hyper/cbrt/hypot/
  inv-hyper) — all oracle-tested vs host libm ≤2–4 ULP.
- G16a locale: setlocale (C/POSIX/C.UTF-8/en_US.UTF-8), localeconv (C-locale
  lconv), nl_langinfo (#1896).
- G16b locale/wchar: UTF-8 multibyte⇄wide codec — decode_utf8/encode_utf8
  (oracle vs Rust core char) + mbrtowc/mbtowc/mblen/mbrlen, wcrtomb/wctomb,
  mbstowcs/wcstombs, mbsrtowcs/wcsrtombs, btowc/wctob, mbsinit; mbstate_t
  8 bytes (#1897).
- Cleared all 65 spec-lint debt entries in math/net/pthread (#1898) — glibc
  spec-lint now EMPTY.

`xtask glibc --check` = exit0, 100 glibc tests.

## NEXT: G16c — locale/wctype.rs
wide-char classification + case mapping: iswalpha/iswdigit/iswspace/iswalnum/
iswupper/iswlower/iswpunct/iswcntrl/iswprint/iswgraph/iswxdigit/iswblank +
towupper/towlower (+ wctype/iswctype, wctrans/towctrans). C/POSIX-locale
semantics (ASCII fast path) + the Unicode simple case-fold/category tables for
the common BMP ranges; oracle = Rust core `char::is_alphabetic` etc. /
`to_uppercase`. Pure inner classify(u32)->mask + towupper/towlower(u32)->u32,
hosted-tested; freestanding C ABI wraps it.
Then: G16d iconv (UTF-8↔UTF-16/32/Latin1), G16e TZ (tzset + TZif parse +
localtime). Then G17 crypt/rt/termios/setjmp, G18 folded-lib stubs +
ld.so.cache + sysroot publish, G19 migrate userspace musl→glibc + retire musl.

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
Continue the loop at **G16c — locale/wctype.rs** (see NEXT above). Branch
`P28-60-glibc-g16c-wctype`.

## Notes
- musl path stays buildable until G19. 59 is DRAFT — edit directly (no R-block).
- P28 prefix is the loop's ad-hoc glibc sequence; not tracked in
  metadata/index.md. Last used P28-59. C-type counter next=91.
- Tracked follow-ups: bit-exact correctly-rounded sqrt; huge-arg trig
  (Payne–Hanek); dedicated f32 libm cores; long double. /etc/hosts + stub DNS
  resolver; nss _r variants/setpwent/getspnam/nsswitch. lazy PLT
  (_dl_runtime_resolve); general-dynamic DTV/__tls_get_addr. stdio
  buffering+putc/getc macros; exact float dtoa; getopt GNU permutation;
  strptime; glob multi-component; IFUNC SIMD string variants (post-rtld, needs
  IRELATIVE); TLS-key destructor invocation at thread exit.
