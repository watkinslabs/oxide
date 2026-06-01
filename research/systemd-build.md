# systemd 259 musl cross-build — validated config (Track D6)

Status: meson setup CLEAN against our staged musl L2 libs (not host glibc);
`src/basic/libbasic.a` BUILDS on musl cross. Next: `libsystemd-shared-259.so`,
then PID1 + units. Build dir + source are gitignored.

## Cross-build mechanics (validated)
1. `vendor/systemd/gen-pc.sh <arch>` — writes minimal pkg-config `.pc` for the
   staged L2 libs into `vendor/<v>/install-<arch>/lib/pkgconfig/` (host libs lack
   our paths; systemd's `dependency()` needs these). Versions match systemd min-checks.
2. meson cross file (build.sh generates per-arch with ABSOLUTE repo paths — NOT
   committed, machine-specific):
   ```
   [binaries] c='musl-gcc' (x86) | '<repo>/vendor/cross/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc' (arm); ar/strip/pkg-config
   [host_machine] system='linux' cpu_family/cpu=x86_64|aarch64 endian='little'
   [built-in options] c_args=['-idirafter','/usr/include']   # x86 kernel UAPI
   [properties] pkg_config_libdir='<colon-joined vendor/*/install-<arch>/lib/pkgconfig>'
   ```
3. `meson setup build --cross-file <file> -Dlibc=musl -Dmode=release <opts>`

## Validated option set (configures clean + libbasic builds)
ENABLE: `-Dkmod=enabled -Dseccomp=enabled -Dopenssl=enabled -Dgcrypt=enabled
-Dblkid=enabled -Dacl=enabled -Dlibidn2=enabled`
DISABLE (lack libs / first-milestone minimal): `-Dtpm2=disabled -Dlibfido2=disabled
-Dpwquality=disabled -Dp11kit=disabled -Dlibcryptsetup=disabled -Dbpf-framework=disabled
-Dvmspawn=disabled -Dmicrohttpd=disabled -Dqrencode=disabled -Dgnutls=disabled
-Dxkbcommon=disabled -Dselinux=disabled -Dapparmor=disabled -Dsmack=false -Dlibcurl=disabled
-Delfutils=disabled -Dlibidn=disabled -Dpam=disabled -Dfdisk=disabled -Dlibarchive=disabled
-Dima=false -Defi=false -Dbootloader=disabled -Dhomed=disabled -Drepart=disabled
-Dsysupdate=disabled -Dukify=disabled -Dman=false -Dhtml=false`
MUSL-REQUIRED disables: `-Dgshadow=false` (musl lacks putsgent/fgetsgent/sgrp).
COMPRESSION off for first milestone: `-Dzstd=disabled -Dlz4=disabled -Dzlib=disabled
-Dxz=disabled -Dbzip2=disabled` (systemd dlopen-wraps zstd/lz4 + needs full header sets:
lz4hc.h/lz4frame.h now staged; zstd needs zstd_errors.h staged — re-enable later).
NOTE: bad option name — it's `-Dfdisk` not `-Dlibfdisk`.

## musl gaps fixed so far
- lz4: staged lz4hc.h/lz4frame.h/lz4file.h/xxhash.h (build.sh updated) — was lz4.h only.
- gshadow: disabled (musl has no <gshadow.h>).
- (expect more in libsystemd-shared / PID1: nss, utmp, some <stdio_ext.h>/<error.h>,
  qsort_r, etc. — systemd 259 has in-tree musl shims for many; disable features / add
  shims as they surface.)

## Next steps
- `ninja -C build src/shared/libsystemd-shared-259.so` → fix surfaced musl issues.
- Then vendor/systemd/build.sh (both arches, generates cross file, gen-pc, meson, ninja
  the needed targets) + stage /lib/systemd/systemd (PID1) + libsystemd-shared + minimal
  units into rootfs; a systemd_probe (link libsystemd) as the first gate-verifiable PR.
- rootfs WILL exceed 128 MiB → bump rootfs(main.rs)+ESP(image_qemu.rs); watch arm boot time.
