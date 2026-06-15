# glibc (oxide-libc)

Our glibc-ABI C standard library, in Rust. Spec: `docs/59`.

Emits `libc.so.6` + (via `crates/user/ldso`) `ld-linux-x86-64.so.2` /
`ld-linux-aarch64.so.1`. Goal: unmodified Fedora `-gnu` binaries link + run.

## Layout (`docs/59§3`)

- `src/<area>/` — one glibc area per module, one public C fn per file.
- `src/arch/<arch>/` — sysdeps: syscall shim, `_start`, TLS, IFUNC, setjmp/clone asm.
- `src/internal/` — no C ABI: errno TLS, syscall `nr` constants, `symver!`.
- `version/<arch>.map` — symbol-version script (`GLIBC_2.x` nodes).
- `abi/<arch>.toml` — frozen ABI goldens; CI diffs the built `.so`.

## Build

- rlib (this crate, workspace + hosted oracle tests): `cargo build -p glibc`,
  `cargo test -p glibc --features hosted`.
- shipped libc (`xtask glibc`, lands incrementally): rebuilds with
  `--crate-type cdylib,staticlib --features freestanding`, the version
  script, and freestanding link flags; publishes into the sysroot.

## Status

G1 skeleton (`docs/59§6`). Areas are stubs until their G-sub-phase.
