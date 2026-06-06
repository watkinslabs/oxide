# Session hand-off

On **main** (B54 + C55 merged). Autonomous high-priority loop running.

## Goals status
1. **Vendor arm cross-builds — DONE (45/46).** Shared `vendor/lib/uapi-stage.sh`
   (x86 stages host UAPI fresh + -isystem; aarch64 uses cross sysroot). 23 swept
   + dhcpcd per-arch + iputils/pam meson fix + shadow (dynamic pam, --disable-
   logind) + util-linux (arm statx wrapper). All verified building BOTH arches.
   PRs #1541 (B54), #1542 (C55) merged.
   - **systemd** is the only one not rebuilt: its meson `Writing build.ninja`
     gets KILLED (~83%) in this dev shell — a resource/OOM kill (no error), same
     class as below. systemd is UNCHANGED + its prebuilt install works.
2. **B54 boot fix — DONE (x86 verified, merged).** PID 1 the Linux way: deleted
   synthetic bringup init + yo/hi/echo; real /lib/systemd/systemd; eager stack
   map (setup_arg_pages); no global-AS fallback; idle loop `sti;hlt` so the timer
   fires (deadline waits resolve). systemd → oxide login → shell, 0 panics.
   - arm CODE sound (elf_arm real-init+prefault+wfi). arm BOOT-verify is
     ENV-BLOCKED here: `xtask rootfs/qemu aarch64` get the whole command KILLED
     (heavy cross-compile/ext4/TCG); `vendor/limine/` empty (no BOOTAA64.EFI);
     `xtask grub --arch aarch64` unsupported. Needs CI smoke-arm or a host that
     can run those. `xtask kernel --arch aarch64` builds fine.
3. **Distribution + kernel=glue syscall work — ongoing.** kernel=glue structural
   refactor done (kmain crate, syscalls crate). Next: x86-verifiable distro
   improvements / open bugs.

## Environment limits (this dev shell)
- Heavy processes get KILLED silently (whole bash command, 0 output): `xtask
  rootfs/qemu aarch64`, qemu-system-aarch64 emulation under load, systemd meson.
- Background-task **stdout is dropped** — run builds FOREGROUND or read the
  build's own logfile. x86 `qemu-system-x86_64` via oxide_drive WORKS (run_login).

## Open distro bugs (x86-verifiable via run_login)
BUG A no-echo at prompt; C cgroup ENOTEMPTY on destroy; F systemd SCM_CREDENTIALS
"without valid credentials"; G login/getty respawn delay; H `rm -rf` tmpfs rc=1.

## First task next iteration
Pick one contained, x86-verifiable distro item (e.g. BUG H tmpfs delete backend),
fix on a fresh branch, verify via run_login, PR+merge. Keep both arches building.
Author = Chris Watkins, no AI trailers.
