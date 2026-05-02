# 29a Userspace Platform

DRAFT 2026-05-02. Dep:`02`,`03`,`07`,`08`,`09`,`15`,`29`,`31`,`39`,`43`.

End-to-end userspace runtime story. Resolves the Rust-std question. Names target triples, libc, language runtimes, dev workflow, distribution. v1 boundary frozen here.

## 1 Filter

v1 = kernel + minimal userspace (init, libc, ld, busybox) that runs unmodified Linux/musl binaries. Everything else (pkg mgr, GUI, distro identity, system updater) → `docs/v2/`.

## 2 Target triples (RESOLVED — supersedes `07§3.3-3.4` `os=oxide`)

**Userspace targets are Linux-look-alike**, not `os=oxide`. Reason: kernel syscall ABI = Linux x86_64; apps don't need to know they're on oxide.

| Target | Use |
|---|---|
| `x86_64-unknown-linux-musl` | userspace x86 (upstream Rust target; std works today) |
| `aarch64-unknown-linux-musl` | userspace arm |

Kernel targets stay `*-unknown-oxide-kernel` per `07§3.1-3.2`. Only userspace targets flip.

What this gives us:
- Stock Rust `std` compiles + works (no std port needed).
- Tokio, hyper, serde, the whole crates.io ecosystem builds unchanged.
- Cross-compile from any Linux/Mac dev box w/ `cargo build --target x86_64-unknown-linux-musl`.
- C apps via `clang --target=x86_64-unknown-linux-musl --sysroot=<ours>`.

What we give up: `#[cfg(target_os="oxide")]` from userspace. Acceptable; we have no userspace-visible feature that needs it in v1.

Migration path (v2): when we add a unique-to-oxide userspace ABI surface, port std to `*-unknown-oxide`, switch user binaries. Until then, Linux-compat is the win.

## 3 libc

Vendored musl fork at `userspace/libc/musl/`. Patches per `29§4`:
- syscall stubs: `arch/x86_64/syscall_arch.h`,`arch/aarch64/syscall_arch.h` use Linux opcodes (already correct since we keep Linux ABI numbering both arches per `15§1`).
- vDSO lookup via auxv `AT_SYSINFO_EHDR`.
- Dynamic linker installed at `/lib/ld-oxide.so.1` (PT_INTERP).

Build via `xtask user`; produces `libc.so.<ver>` + static `libc.a` + headers in `usr/include/`.

Fork divergence policy: minimum required to function. Track upstream musl tags; rebase patches on each musl release.

## 4 Dynamic linker

`/lib/ld-oxide.so.1` = our ld.so. Built from `userspace/dynlink/` against the same musl. Path conventions:

| Path | Use |
|---|---|
| `/lib/ld-oxide.so.1` | dynamic linker (PT_INTERP) |
| `/lib/libc.so.<musl-ver>` + `/lib/libc.so` symlink | musl runtime |
| `/lib/libdl.so` → `libc.so` | musl ships these in libc |
| `/lib/libpthread.so` → `libc.so` | same |
| `/lib/librt.so` → `libc.so` | same |
| `/lib/libm.so` → `libc.so` | same |
| `/lib/libutil.so` → `libc.so` | same |
| `/lib/libcrypt.so` → `libc.so` | same |
| `/usr/lib/<libname>.so.<v>` | userspace shared libs |
| `/usr/local/lib/...` | site-installed |

soname versioning = standard ELF `SONAME` + symlink chain. We do not invent a versioning scheme.

## 5 App dev workflow

Standard cross-compile-from-Linux flow.

**Rust app**:
```
$ cargo new my-app
$ cargo build --target x86_64-unknown-linux-musl --release
$ cp target/x86_64-unknown-linux-musl/release/my-app <oxide-image>/usr/bin/
```
Drop into initramfs or persistent rootfs. Run on QEMU.

**C app**:
```
$ clang --target=x86_64-unknown-linux-musl --sysroot=$OXIDE_SYSROOT \
        -static -O2 my.c -o my-app
```
Or use musl-cross-make for a standalone musl-gcc. Either works.

**Go app**: `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build`. Drop binary in. Go runtime exercises `clone3`, `futex`, `epoll`, `mmap`, `tgkill`; all V1 in `15`.

No oxide-specific SDK. The dev environment is "Linux cross-compile target." This is the embedded-dev pattern; works for kernel+QEMU dev today.

`xtask user` wraps the above for in-tree apps (`userspace/apps/<name>/`).

## 6 Language runtime matrix

| Runtime | v1 | v1.x | v2 |
|---|---|---|---|
| C (musl-static / -dynamic) | ✓ | — | — |
| Rust (musl-static / -dynamic) | ✓ | — | — |
| Go (static) | ✓ (per `43§2`) | — | — |
| C++ (libstdc++ / libc++) | ✗ | ✓ | — |
| Python 3 (CPython) | ✗ | ✓ | — |
| Node.js | ✗ | ✗ | ✓ |
| Java (OpenJDK) | ✗ | ✗ | ✓ |

C++ ships v1.x because no v1 acceptance binary needs it (busybox, redis, nginx, openssh, sqlite are all C). Python via stock CPython musl-static build; needs v1.x because Python ships in modern distros.

## 7 Package distribution

v1: **none**. Apps shipped as static binaries built into the kernel image (per `39§5` initramfs layout).

v1.x options (TBD; not blocking):
- **tarball + extract**: simplest; per-app `<name>.tar.zst` extracted to `/usr/`.
- **APK** (Alpine): musl-native, simple format, mature tooling. Lean if we add one.

v2: real package manager + repo infrastructure. Out of scope.

## 8 /usr filesystem layout (frozen)

Standard FHS subset:

| Path | Use |
|---|---|
| `/bin/`, `/sbin/` | merged-`/usr/bin` symlinks; binaries |
| `/usr/bin/` | most user binaries |
| `/usr/sbin/` | system daemons |
| `/usr/lib/` | shared libs (besides `/lib/libc.so`) |
| `/usr/local/bin`,`/usr/local/lib` | site-installed |
| `/usr/share/` | arch-indep data |
| `/usr/include/` | dev headers (in dev image only) |
| `/var/{log,cache,lib,run}` | mutable state |
| `/etc/` | config (per `29§7`) |
| `/tmp/` | tmpfs |
| `/home/<user>/` | per-user |
| `/root/` | root home |

Merged-`/usr` (`/bin`→`/usr/bin`, `/lib`→`/usr/lib`): yes, modern Linux convention.

## 9 PAM / NSS / locale (v1 minimal)

- PAM: not implemented v1. login reads `/etc/passwd`+`/etc/shadow` directly using musl's crypt (Argon2id only).
- NSS: musl's built-in `files dns` only. No nsswitch.conf modules in v1.
- Locale: `C.UTF-8` and `en_US.UTF-8` only. musl handles UTF-8 natively; no glibc-locale-archive needed.

v1.x: PAM stub allowing third-party modules; full nsswitch; more locales as `.charmaps/`.

## 10 Service management (v1 minimal)

`init` per `29§3`. Spawns services from `/etc/init.conf`. Restart policy `on-failure|always|never`. Reaps zombies.

No socket activation, no per-service cgroup, no dependency graph. v1.x: maybe minimal s6/runit-class supervisor. v2: systemd if anyone needs it.

## 11 Compatibility surface (what apps can rely on)

App can depend on:
- Linux x86_64 syscall ABI (per `15`; numbers + semantics).
- musl libc 1.2.x semantics (vendored).
- vDSO `clock_gettime`/`getcpu`/`gettimeofday` per `15§8`.
- `/proc`,`/sys`,`/dev`,`/etc/passwd` Linux-format compat per `19`+`29`.
- POSIX threads (NPTL-style) via musl pthreads → kernel `clone3`.
- File modes / permissions / ACLs (xattr; ACL via xattr; no full POSIX ACL syscall).
- TCP/UDP/IPv6/AF_UNIX with Linux socket-option semantics (per `25`).

App cannot rely on (v1):
- io_uring (v1.x).
- BPF (v1.x).
- systemd interfaces (v2).
- Real TTY ECHO line discipline beyond modern bash interactive (covered) — no SLIP/PPP.
- `/proc/sys/net/...` runtime-tuned via sysctl; many entries return ENOENT in v1.

## 12 Test contract (frozen)

- `cargo build --target x86_64-unknown-linux-musl --release` of a Tokio hello-world TCP echo server produces a binary; binary runs on QEMU image; `curl localhost:8080` succeeds.
- `clang --target=x86_64-unknown-linux-musl --sysroot=...` builds redis 7 from upstream source; runs on image.
- Stock musl-static Go binary that uses goroutines + channels + http.Server: builds, runs, serves.
- `/lib/ld-oxide.so.1` resolves dependencies of a dynlinked binary; at least one v1 binary is dynlinked end-to-end (the rest static).
- `getpid`,`getuid`,`getgid` return ABI-shaped values; `uname()` returns "oxide" sysname (or "Linux" — see OQ).

## 13 Failure modes

- Binary built for `*-unknown-oxide` (kernel target) executed in userspace: ENOEXEC at loader (we never produce these for user).
- Dynamic-link to nonexistent lib: ELIBBAD per `31§9`.
- Older musl version mismatched soname: ELIBBAD; user must rebuild against current sysroot.

## 14 Cross-spec

`07§3.3` (userspace targets resolved to upstream `*-unknown-linux-musl` per §2 above; no custom JSON), `15` (syscall ABI compat), `29` (init+image+/etc), `31` (ELF loader+dynlink), `39` (build+image+sysroot publication), `43§2-4` (acceptance bins must build per this workflow).

## 15 Changelog

(none)

## 16 OQ

- `uname()` `sysname` field: "Linux" (max app compat — bash version checks etc) or "oxide"? Lean: "Linux" for v1 (our charter is run-Linux-binaries-unmodified; lying here is consistent w/ `07§3.3` lying about LLVM target). v2: "oxide" once distinct ABI lands.
- musl version pin: 1.2.5 today; bump policy = follow upstream tags; document in `tools/musl-bump.sh`.
- C++ runtime choice when v1.x: libstdc++ (gcc) or libc++ (LLVM)? Lean: libc++; we already use clang/LLVM elsewhere.
- Static-vs-dynamic default for v1 in-tree apps: **static** (simpler, no dynlink bring-up issues). One demo binary dynlinks to validate ld-oxide.
- App distribution v1.x: APK vs tarball. Defer pick.
- Sysroot publication: `xtask user --sysroot` produces `target/sysroot-<arch>/` with `usr/include/` + `usr/lib/`; consumed by external app builds. Document in `39`.
