# Session hand-off

## Headline
L2 shared-lib tree COMPLETE (17 deps) + **arm openssl unblocked** (F347 #1459, catchable
SIGILL). Now in **Track D6 — systemd** (kickoff done: fetched + toolchain validated).
Branch: `main` clean @ #1459.

## Done this session (merged)
- B51 #1447 bounded-retry boot gate; L2 deps #1448-1455 (expat,dbus,libgpg-error,libgcrypt,
  attr,acl,kmod,openssl,libunistring,libidn2) via the C40 `l2_deps` table; rootfs 32→128 MiB
  + disk/ESP 64→512 MiB (#1454); dyn_probe cross-vendor -rpath-link.
- **F347 #1459 — aarch64 catchable synchronous-fault SIGILL.** arm EL0 EC=0 undefined-instr
  → `oxide_undef_save_block` (vbar.rs, mirrors softstep) → `oxide_arm_undef_handler`
  (fs/ptrace.rs) → `sig_dispatch::deliver` catchable SIGILL. Boot-verified: openssl_probe
  rv=0 on arm + login. openssl_probe un-gated (both arches). Resolved the sole D6-on-arm blocker.

## Open work — D6 systemd (in order)
**Kickoff DONE:** systemd 259 fetched to `vendor/systemd/systemd-259` (sha
a84123692d1add7f9c48fd11cdf5f901393008c2d2ade667c18f25a20bf1290d, tools/fetch-systemd.sh TBD);
host tools present (meson 1.10, ninja, gperf 3.1, python3+jinja2 3.1). `meson setup` WORKS but
found HOST glibc libs (pkg-config leaked /usr/lib/pkgconfig) — wrong for musl target.
1. **meson cross-file isolation** (the crux): write `vendor/systemd/cross-{x86_64,aarch64}.txt`
   meson cross files — `[binaries]` musl-gcc / aarch64-linux-musl-*, `[built-in options]`
   c_args+=`-idirafter /usr/include` (x86 UAPI), `[properties] pkg_config_libdir` pointing ONLY
   at our staged L2 pkgconfig dirs (NOT host). Treat x86 as cross too (musl≠host glibc).
2. **.pc files**: only zlib has one staged. Generate/stage pkgconfig `.pc` for the L2 libs
   systemd needs (libcap, openssl, libgcrypt+libgpg-error, libseccomp, kmod, blkid/mount/uuid,
   acl, attr, libidn2, pcre2, zstd, lz4) into `vendor/<v>/install-<arch>/lib/pkgconfig/` (most
   autotools builds generate a .pc in-tree — stage it; else hand-write).
3. **feature flags** (recipe in research/systemd-musl.md + research/arm-sigill-fix.md sibling):
   `-Dlibc=musl -Dmode=release`; ENABLE kmod/seccomp/openssl/gcrypt/blkid/acl; DISABLE the
   optional dlopen feats we lack (tpm2/libfido2/pwquality/p11kit/libcryptsetup/bpf-framework/
   microhttpd/qrencode/gnutls/xkbcommon/selinux/apparmor/smack/libcurl/elfutils/...). musl
   auto-disables nss-*/homed/userdbd/DynamicUser.
4. Build INCREMENTALLY, land per-PR: libsystemd-shared + a systemd_probe first; then PID1
   (/lib/systemd/systemd) + minimal units staged to rootfs. systemd is BIG → rootfs >128 MiB →
   bump rootfs(main.rs count=)+ESP(image_qemu.rs count=) together; watch dumpe2fs free + arm
   boot time (embedded-rootfs grows kernel/slows arm TCG → maybe bump arm smoke timeout
   (.githooks/pre-push) or move rootfs→virtio-blk disk). Fix surfaced kernel gaps in-PR.

## First command (next session)
systemd cross-build VALIDATED (research/systemd-build.md): meson setup clean vs our
musl libs, `src/basic/libbasic.a` builds. systemd libs build BOTH arches (libsystemd-shared + libsystemd); F348 stages libsystemd.so + systemd_probe (rv=0 both arches — first systemd code runs on oxide). NEXT: PID1 /lib/systemd/systemd + units (F349); libsystemd-shared built+installed, ready.
(fix surfaced musl gaps), then write `vendor/systemd/build.sh` (both arches: gen cross file
+ gen-pc.sh + meson + ninja the needed targets) + stage PID1/libsystemd-shared + minimal units
+ a systemd_probe → first gate-verifiable PR F348. `vendor/systemd/gen-pc.sh <arch>` writes the
.pc files; exact validated meson option set is in research/systemd-build.md.

## CRITICAL harness rules
- Both-arch gate via backgrounded PLAIN `git push` (run_in_background+dangerouslyDisableSandbox;
  `git push 2>FILE; echo PUSH_DONE rc=$?>>FILE`). rc=0=pass. rc=141/"closed" but gate PASSED →
  re-push `SKIP_SMOKE=1`. "host forwarding tcp::2222" → stale qemu squats port → clear ports
  (ss 2222/1234 + pgrep `system-aarch64`/`system-x86_64` pid; NEVER `pkill -f qemu`=self-kill).
- ALWAYS kill local verify-boot qemu by port+pid after each boot (squatters false-fail the gate).
- Watch rootfs free (`dumpe2fs`) as deps grow (overflow → silent file-drop → arm pre-init wedge).
- spec-lint clean before commit/PR; `main.rs` AT 1000-line cap (refactor before edit); branch
  per change; revert dirtied `kernel/blobs/rootfs-*.img` before commit; explicit `git add <paths>`.
- Follow-up: x86 #UD→catchable-SIGILL parity mirror (hal-x86_64/fault.rs); refine no-handler
  SIGILL wstatus 11→4. (x86 openssl already works; not blocking.)
