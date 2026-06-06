# Session hand-off

Branch: **B54-pid1-real-execve-path** (5 commits ahead of main, unpushed).
Autonomous high-priority run: (1) all vendor **arm** cross-builds work, (2) arm
branch at par with x86 (B54 boots arm→login), (3) continue the distribution +
kernel=glue syscall work. Loop armed (ScheduleWakeup).

## Done + verified this run
- **kernel = pure glue** (PR #1540 on main): kernel crate eliminated → `kmain`
  (`crates/kernel/kmain/src/kmain.rs`); subsystems/devices in crates; timers
  self-register (docs/56); blobs gitignored + built on demand (`ensure_blobs`).
- **B54 (x86, VERIFIED):** PID 1 boots the Linux way — synthetic bringup init
  (ELF_BLOB + yo/hi/echo) deleted; real `/lib/systemd/systemd` loaded; eager
  stack map (`pmm::user_as::prefault_stack` = setup_arg_pages); **no global-AS
  fallback** (fault handler resolves current->mm only). Root-cause fix: idle
  loop must `sti; hlt` so the timer fires → deadline waits (systemd terminal
  ppoll) resolve. systemd → `oxide login:` → shell, 0 panics.
- **Vendor arm cross-build fix:** `vendor/lib/uapi-stage.sh` (x86 stages host
  UAPI fresh + -isystem; aarch64 uses cross sysroot, no host headers). Swept 23
  build.sh's onto it (dhcpcd + coreutils verified building both arches). dhcpcd
  per-arch (`build.sh x86|arm|all`); Makefile `vendor-x86`/`vendor-arm` +
  `vendor-rebuild ARCH=`.

## OPEN
1. **Vendor sweep unfinished:**
   - meson pkgs (pam, systemd, dbus, …) use cross-file `'-isystem','$HDRS_ARM'`
     — the sweep regex MISSED them; fix to use cross sysroot for arm.
   - **pam ships shared-only**; shadow links `-static -lpam` → needs libpam.a.
     Per-package static-vs-shared decision.
   - make every build.sh arch-aware (only dhcpcd is); dep-ordered rebuild.
   - then `make vendor-rebuild` green BOTH arches. Verify each: `bash
     vendor/<pkg>/build.sh` FOREGROUND (background stdout is dropped here).
2. **arm boot-verify HARD-BLOCKED in this dev shell:**
   - `xtask rootfs --arch aarch64` + `xtask qemu --arch aarch64` get the whole
     command KILLED silently (heavy cross-compile / ext4 image / TCG). `xtask
     kernel --arch aarch64` builds fine; a *direct* qemu-system-aarch64 runs.
   - `vendor/limine/` is EMPTY → no `BOOTAA64.EFI`; `xtask grub --arch aarch64`
     unsupported (grub bootstrap x86-only). So no arm boot image can be
     assembled here. Needs `tools/fetch-vendor.sh` (limine) + a host that can
     run xtask rootfs/qemu arm (or CI smoke-arm).
   - arm CODE is sound: elf_arm already real-init+prefault+wfi-idle; my only arm
     change = shared global-AS-fallback removal (safe, arm prefaults).
3. **Merge B54 → main** once arm confirmed (or via CI). x86 already verified.

## First task next iteration
Goal 1: fix meson cross-file -isystem in vendor/{pam,dbus,systemd,...}/build.sh
(use cross sysroot for arm), verify FOREGROUND. Then pam-static for shadow.
Then merge B54 (x86-verified) so main has the boot fix. Goal 2 arm-boot: try
`tools/fetch-vendor.sh` for limine; if xtask rootfs/qemu still get killed, it's
a host limit — report to user.
