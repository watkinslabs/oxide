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

## NEXT: G19 — migrate userspace musl→glibc + retire musl (FINAL rung)
The whole oxide-libc exists; G19 makes the userspace actually use it, then
removes musl. This is the lockstep + boot phase (not pure hosted code):
- Point the userspace build/targets at the oxide glibc sysroot
  (target/sysroot/<triple>) instead of `*-unknown-linux-musl`. Audit how
  userspace is currently built (docs/29a, tools/xtask rootfs*, vendor cross-
  builds) and switch the libc/sysroot + dynamic-linker.
- A real dynamic exe with a normal `main` needs an Scrt1.o-equivalent (our
  `crt` feature builds _start into libc.a; for dynamic PIEs we likely need a
  standalone Scrt1.o that calls __libc_start_main). Provide it if missing —
  this is the one known gap the G18c smoke side-stepped with -nostartfiles.
- Rebuild userspace (at minimum the existing bins; ideally bash/coreutils per
  29a) against the sysroot. Fix glibc-vs-musl gaps as they surface (missing
  syscalls, struct sizes, symbol versions).
- Boot BOTH arches to `oxide login:` via the qemu MCP
  (mcp__qemu__qemu_start arch=x86_64 AND arch=aarch64) — lockstep, verified,
  not "should work".
- Remove musl from the build once both boot. Then docs/59 ladder is COMPLETE:
  mark 59 FROZEN/done + update CLAUDE.md status line.

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
  metadata/index.md. Last used P28-69. C-type counter next=91. D-type next=100.
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
