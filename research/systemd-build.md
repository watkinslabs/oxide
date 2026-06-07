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

## Progress (build grind toward libsystemd-shared)
- libbasic.a BUILDS. libsystemd-shared compiling; fixed so far:
  - lz4 full headers staged; compression (zstd/lz4/zlib/xz/bzip2) disabled for 1st milestone.
  - gshadow disabled (musl).
  - gcrypt disabled (systemd finds -lgcrypt via find_library → no pkg-config Cflags → gcrypt.h
    not found; re-enable later by forcing the include, or accept FSS-off).
  - acl/attr installed headers: stripped the leaked `EXPORT` visibility macro (EXPORT→extern)
    in install-<arch>/include — systemd's acl-util.c now compiles. (TODO: also sed it in
    acl/attr build.sh stage step for reproducibility; staged dirs already fixed+committed.)
  - util-linux .pc Cflags now add the per-lib include subdir (blkid/libmount/uuid/libsmartcols)
    so `<blkid.h>` resolves — gen-pc.sh updated. MUST wipe+re-setup meson after .pc changes
    (meson caches dependency resolution).
- **NEXT BLOCKER: nss.h glibc leak.** `src/shared/nss-util.c` does `#include <nss.h>`; musl has
  no nss.h, so `-idirafter /usr/include` (needed for kernel UAPI linux/*.h) pulls the HOST glibc
  nss.h → "expected ';' before 'enum'" (glibc-ism). FIX OPTIONS: (a) provide a minimal musl nss.h
  shim in vendor/systemd/musl-shims/ + add `-I <that>` to c_args BEFORE the -idirafter (shadows
  glibc's) — stub needs `enum nss_status {TRYAGAIN=-2,UNAVAIL=-1,NOTFOUND=0,SUCCESS=1,RETURN=2}`
  + whatever nss-util.h references; OR (b) find the meson option/feature that pulls nss-util.c
  into libsystemd-shared and disable it (nss-* are already disabled; userdb/nscd may pull it).
  The shim dir is reusable for other glibc-only headers that leak via -idirafter.

## MILESTONE: x86 systemd core libs BUILD
- `libsystemd-shared-259.so` (12 MB) + `libsystemd.so.0.42.0` build + link on musl x86
  against our staged L2 libs. nss.h glibc-leak fixed via vendor/systemd/musl-shims/nss.h
  (-I<shim> in c_args, single-token form — two-token `-I dir` breaks meson's sizeof probe).
  vendor/systemd/build.sh does both arches (generates per-arch cross file + gen-pc + meson + ninja).
- **ARM BLOCKER: old UAPI in the cross toolchain.** systemd's src/include/musl/sys/stat.h
  static_asserts `struct statx` (kernel 4.11+); the aarch64-linux-musl-cross sysroot's
  <linux/stat.h> predates statx, and `-idirafter /usr/include` is LOWER priority than the
  sysroot system headers so it can't override. FIX (next tick): stage modern Linux generic
  UAPI (host /usr/include/linux is arch-independent for struct statx) into a dir and add it
  as a HIGH-priority `-I<dir>` (or -isystem before sysroot) in the ARM c_args ONLY for the
  generic linux/ headers (NOT asm/ — that's arch-specific; the cross sysroot's asm/ is correct).
  Simplest: `cp -r /usr/include/linux vendor/systemd/musl-shims/linux` (or just the needed
  headers) + the existing -I<shim> picks it up (shim dir is already a -I). Verify it doesn't
  shadow arch-specific headers. Then arm libsystemd-shared should build (modulo more arm gaps).
- Until arm builds, F348 (both-arch) can't ship; x86 build + build.sh + shims are committable infra.

## MILESTONE 2: PID1 + systemctl build BOTH arches
- vendor/systemd/build.sh now builds + installs (both arches): libsystemd-shared-259.so,
  libsystemd.so.0.42.0, libsystemd-core-259.so, /lib/systemd/systemd (PID1, ~309 KB),
  bin/systemctl (~790 KB).
- Two more fixes added: (a) GLOBAL L2 include dirs in c_args (meson propagates pkg-config
  Cflags to libshared but NOT to libcore/executables — e.g. exec-credential.c includes
  <acl/libacl.h>; so add -I<each L2 include> + util-linux subdirs globally; linking still
  via pkg-config); (b) arm c_link_args += -Wl,-rpath-link,<each L2 libdir> so the strict
  arm cross-ld resolves libsystemd-shared.so's transitive DT_NEEDED (libcrypto@OPENSSL_3.0.0)
  when linking the executables.
- PID1 DT_NEEDEDs libsystemd-core-259.so + libsystemd-shared-259.so + ld-musl. Its baked
  RUNPATH is BUILD-TREE paths ($ORIGIN/src/core:...:vendor/openssl/.../lib) — nonexistent on
  target, so ld-musl skips them and falls back to /usr/lib. So stage both private .so's into
  /usr/lib (where musl ld.so + our other L2 libs already resolve).

## F349 staging plan (NEXT — needs main.rs line-budget refactor; it's AT 1000)
Stage into rootfs (dedicated systemd block, NOT l2_deps — extract a helper or add a
l2_deps::SYSTEMD_STAGE const + loop to keep main.rs <=1000):
  /lib/systemd/systemd            <- install-<arch>/lib/systemd/systemd
  /usr/lib/libsystemd-core-259.so <- install-<arch>/lib/libsystemd-core-259.so
  /usr/lib/libsystemd-shared-259.so
  /usr/bin/systemctl
(libsystemd.so* already staged via l2_deps F348.)
Then F349 verify = rcS `/lib/systemd/systemd --version` → rv=0 BOTH arches (proves the big
PID1 binary + its private libs load on musl). F350+: systemd as init reaching a target
(surfaces kernel gaps — fix in-PR). rootfs after staging: ~+8 MB (core 6.3MB + pid1 + systemctl)
→ check dumpe2fs; arm currently ~50/128.

## Next steps
- `ninja -C build src/shared/libsystemd-shared-259.so` → fix surfaced musl issues.
- Then vendor/systemd/build.sh (both arches, generates cross file, gen-pc, meson, ninja
  the needed targets) + stage /lib/systemd/systemd (PID1) + libsystemd-shared + minimal
  units into rootfs; a systemd_probe (link libsystemd) as the first gate-verifiable PR.
- rootfs WILL exceed 128 MiB → bump rootfs(main.rs)+ESP(image_qemu.rs); watch arm boot time.

## F350 recon: systemd PID1 boots into early init (hangs at mount_setup/sd-event)
Temporarily made PID1 = /lib/systemd/systemd (kernel/src/smoke/elf.rs init lookup) +
systemd.log_level=debug on the limine cmdline. systemd PID1 RUNS on oxide x86:
  systemd → "[1]:" → "System time advanced to built-in epoch: 2025-12-17..." →
  "Failed to turn off coredumps, ignoring: No such file or directory" (non-fatal:
   missing /proc/sys/kernel/core_pattern or prctl) → garbled "P+q<hex 'name'>\" → HANG.
So systemd PID1 starts + does time-setup + coredump-setup, then HANGS very early
(next in src/core/main.c is mount_setup() → mounts /proc /sys /dev /run /sys/fs/cgroup;
or the manager/sd-event init). Debug logs don't flush past the hang → stuck in a syscall.
NEXT (F350 fix): boot systemd-PID1 with KERNEL syscall tracing (--features debug-all or a
targeted trace) to see the exact stuck syscall (likely a mount(2) with flags/opts our mount
mishandles, OR epoll/signalfd/timerfd for sd-event, OR a blocking read). Fix that ONE gap
(most mount/cgroup/epoll/signalfd/timerfd machinery exists from Track K — wire/extend).
Iterate: each gap gets systemd further. Keep the prior minimal-init as the gate's default PID1
(login smoke) while iterating systemd-as-init via the temp elf.rs swap locally OR a init= cmdline branch.
Recon edits (elf.rs PID1→systemd, image_qemu cmdline debug) were REVERTED — reapply locally to iterate.
