# 29a Userspace Platform

FROZEN 2026-05-02. Dep:`02`,`03`,`07`,`08`,`09`,`15`,`29`,`31`,`39`,`43`,`51`.

End-to-end userspace runtime story. Names the userland supplier, libc, loader, language runtimes, distribution. Substrate frozen here.

## 1 Filter

Substrate = kernel + Fedora glibc userland (systemd, glibc, bash, coreutils, util-linux) running unmodified. Pkg mgr, GUI, distro identity, system updater land in their own phases per `00§3` (phases 28–32).

## 2 Userland supplier (RESOLVED — this repo builds no userspace)

Userspace is **upstream Fedora**, installed from RPMs. Composition — package set, `/etc`, users, image packing — is owned by the sibling `../images` repo (`imagectl` + `dnf5`), which emits `output/<profile>-<arch>-root.img`. This repo consumes that image (`29§4.1`) and owns nothing inside it.

| Item | Value |
|---|---|
| binary ABI | Fedora `x86_64-unknown-linux-gnu` / `aarch64-unknown-linux-gnu` |
| libc | Fedora `glibc` RPM (`libc.so.6`, `GLIBC_2.x` version nodes, IFUNC) |
| loader | `/lib64/ld-linux-x86-64.so.2`, `/lib/ld-linux-aarch64.so.1` |
| PID 1 | Fedora `systemd` RPM (`51§2`) |

Kernel targets stay `*-unknown-oxide-kernel` per `07§3.1-3.2`.

What this gives us: every Fedora binary is a conformance test, and any failure is a kernel bug with a Linux-defined correct answer.

What we give up: `#[cfg(target_os="oxide")]` from userspace, and any ability to patch around a kernel gap in libc. Both intentional.

## 3 libc

Fedora `glibc`, unmodified. No fork, no patches, no in-tree build. Consequences that bind the kernel:
- Syscall numbering + calling convention per arch exactly as Linux (`15§1`,`15§2`); aarch64 is asm-generic, so glibc composes `open`/`stat`/`fork` from `openat`/`newfstatat`/`clone`.
- vDSO discovered via auxv `AT_SYSINFO_EHDR` with Linux symbol names + signatures (`15§8`).
- ABI struct layouts (`15§6`), errno table (`01§6`), signal numbers (`01§7`) are Linux's, not ours.

A behavior glibc relies on that the kernel gets wrong is a kernel defect: fix the kernel (`02§3`).

## 4 Dynamic linker

Fedora's `ld-linux`, shipped by the `glibc` RPM, named by `PT_INTERP` in every dynamic binary. Kernel obligation is the `PT_INTERP` chain + auxv contract only (`31§5`). Path conventions:

| Path | Use |
|---|---|
| `/lib64/ld-linux-x86-64.so.2` | loader, x86_64 (PT_INTERP) |
| `/lib/ld-linux-aarch64.so.1` | loader, aarch64 |
| `/lib64/libc.so.6` | glibc runtime |
| `/lib64/libpthread.so.0`,`libdl.so.2`,`librt.so.1` | folded into `libc.so.6` since glibc 2.34; Fedora ships the stubs |
| `/usr/lib64/<libname>.so.<v>` | RPM-installed shared libs |
| `/usr/local/lib/...` | site-installed |

soname versioning = standard ELF `SONAME` + symlink chain, as Fedora ships it.

## 5 Getting a binary onto the image

Two supported routes, both outside this repo:
- Add the package to the profile's package set in `../images`; `dnf5` installs it from the Fedora mirror or from a local oxide RPM.
- Build an RPM in the sibling `../packages` repo, then reference it from a profile.

Ad-hoc: copy a Fedora `-gnu` binary into the mounted image. No cross-compile toolchain, no sysroot, and no SDK is published from this repo; `vendor/cross` was deleted with the userspace tree.

Kernel-side conformance probes (`userspace/`) are the exception: small C/Rust programs built against the host GNU toolchain to exercise one syscall contract, staged into the image for a boot test. They are tests, not userland.

## 6 Language runtime matrix

Every row is "whatever Fedora ships for that arch"; the gate is the kernel surface each runtime exercises.

| Runtime | Exercises | Phase |
|---|---|---|
| C (glibc, dynamic) | the whole ABI | now |
| Rust (`-gnu`) | glibc + `clone3`/futex | now |
| Go (static) | `clone3`, futex, epoll, mmap, tgkill | now (per `43§2`) |
| C++ (libstdc++) | unwinder, TLS, `dl_iterate_phdr` | 28 |
| Python 3 (CPython) | dlopen, locale, NSS | 28 |
| Node.js | epoll, threads, io_uring | 30 |
| Java (OpenJDK) | mmap-heavy, signals, perf | 30 |

## 7 Package distribution

`dnf5` + RPM, as Fedora does it. Repo composition lives in `../images`; locally built packages come from `../packages`. Nothing is baked into the kernel image by this repo except the kernel itself.

## 8 /usr filesystem layout (frozen)

Standard FHS subset:

| Path | Use |
|---|---|
| `/bin/`, `/sbin/` | merged-`/usr/bin` symlinks; binaries |
| `/usr/bin/` | most user binaries |
| `/usr/sbin/` | system daemons |
| `/usr/lib/`, `/usr/lib64/` | shared libs |
| `/usr/local/bin`,`/usr/local/lib` | site-installed |
| `/usr/share/` | arch-indep data |
| `/usr/include/` | dev headers (in dev image only) |
| `/var/{log,cache,lib,run}` | mutable state |
| `/etc/` | config (per `29§7`) |
| `/tmp/` | tmpfs |
| `/home/<user>/` | per-user |
| `/root/` | root home |

Merged-`/usr` (`/bin`→`/usr/bin`, `/lib`→`/usr/lib`): yes, modern Linux convention.

## 9 PAM / NSS / locale

Fedora's own, from RPMs: `pam` modules under `/usr/lib64/security/`, glibc NSS modules driven by `/etc/nsswitch.conf`, glibc locale archive. `login` authenticates through PAM. Kernel obligations are the syscalls those libraries make (`openat`, `dlopen` path, `keyctl`, `setgroups`), not the policy.

## 10 Service management

systemd, per `51§2-3`: unit dependency graph, socket activation, per-service cgroup, journald. Kernel obligations: cgroup v2 (`26`), `pidfd`/`waitid` (`13`), `signalfd`/`timerfd`/`epoll` (`15`), `/dev/kmsg` (`19`).

## 11 Compatibility surface (what apps can rely on)

App can depend on:
- Linux syscall ABI both arches (per `15`; numbers + semantics).
- glibc semantics as Fedora ships them.
- vDSO `clock_gettime`/`getcpu`/`gettimeofday` per `15§8`.
- `/proc`,`/sys`,`/dev`,`/etc/passwd` Linux-format compat per `19`+`29`.
- POSIX threads (NPTL) → kernel `clone3`.
- File modes / permissions / ACLs (xattr; ACL via xattr; no full POSIX ACL syscall).
- TCP/UDP/IPv6/AF_UNIX with Linux socket-option semantics (per `25`).

App cannot yet rely on:
- BPF (phase 23).
- Real TTY ECHO line discipline beyond modern bash interactive (covered) — no SLIP/PPP.
- `/proc/sys/net/...` runtime-tuned via sysctl; many entries currently return ENOENT.

## 12 Test contract (frozen)

- Fedora `bash`+coreutils+util-linux from the image run: `bash -c 'echo hello | wc -c'` → `6`.
- Fedora `systemd` reaches its default target and `agetty` prints `oxide login:` on both arches (`make smoke-x86`, `make smoke-arm`).
- A Fedora dynamic binary resolves its `DT_NEEDED` graph through `ld-linux` end-to-end; `ldd` on the image agrees with the loader.
- Fedora `python3` imports a C extension (`dlopen` + TLS + NSS path).
- `getpid`,`getuid`,`getgid` return ABI-shaped values; `uname()` sysname is "Linux".

## 13 Failure modes

- Binary built for `*-unknown-oxide-kernel` executed in userspace: ENOEXEC at loader.
- Dynamic-link to nonexistent lib: ELIBBAD per `31§9`.
- Mismatched soname after a partial image compose: ELIBBAD; recompose the profile in `../images`.

## 14 Cross-spec

`07§3.3` (no userspace target owned here), `15` (syscall ABI compat), `29` (init + image consumption + `/etc`), `31` (ELF loader + dynlink), `39` (build + image), `43§2-4` (acceptance binaries).

## 15 Changelog

- 2026-05-14: v1/v2 framing stripped per `02§9` rule 8. Deferred-feature cells now point at `00§3` phase numbers.
