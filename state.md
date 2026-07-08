# Handoff — glibc quick-boot done; boot-to-GNOME blocked on intermittent hang

**Branch:** `F693-quickboot-glibc-rootfs` (pushed, PR #2837). 8 commits, all boot-tested where possible.
**Goal in flight:** graphical GNOME desktop booting to a visible greeter, 100% Linux-compat, no stubs.

## DONE + verified (on the branch)
- **musl → glibc quick-boot.** `xtask rootfs` (`rootfs_glibc.rs`) now COPIES the images-repo
  pre-packed glibc image `../images/output/<profile>-<arch>-root.img` (default `live-gnome`)
  as `root-<arch>.img` (cp --reflink, instant on btrfs). No dnf/sudo in the kernel repo.
  Boot-verified: reaches systemd `graphical.target` + gdm, 57 ld-linux, **zero ld-musl**.
- Deleted the musl staging (rootfs/{build,stage_system,stage_tools}, rootfs_{lists,dynprobe,etc,cache},
  l2_deps) + 92 tools/fetch-*.sh + 1197 tracked musl vendor build artifacts + dead vendor/limine.
  KEPT vendor/{firmware,grub,lib} + upstream source tarballs (packagectl builds glibc RPMs from those).
- `make qemu-x86` / MCP default to **KVM + 4G** (was TCG/2G → GNOME impractically slow).
- **rw root + service masks** (image_qemu/x86_64.rs cmdline): `root=... rw` (was `ro` → WRITE-EROFS)
  + mask zram/firewalld/chronyd/ModemManager/plymouth/NM-wait-online. Cut graphical.target 137s→52s.
- Per-op display-stack traces ([futex park]/[VTIO]/[TGKILL]/[waitid]) moved to opt-in
  `debug-displaystack` feature (were flooding serial under debug-boot / ungated).
- boot-smoke marker → `Reached target basic.target` (glibc gnome has no serial `oxide login:`).

## DONE, correct, but UNVERIFIED end-to-end (426b3819)
- **DRM VIRTGPU_GETPARAM/GET_CAPS** implemented (drm uapi/core_api/node.rs + drv-virtio-gpu device.rs).
  Root cause found via [DRMIOCTL] trace: Mesa's `virtio_gpu` driver (DRM VERSION name="virtio_gpu")
  probes GETPARAM(0x43)/GET_CAPS(0x49) after opening card0; kernel returned ENOTTY → Mesa can't
  decide 3D → loops, mutter never reaches KMS (GETRESOURCES/SETCRTC=0). Fix: PARAM_3D_FEATURES=0
  (no virgl; device didn't negotiate F_VIRGL) → Mesa falls back to llvmpipe over KMS dumb-buffer.
  UNVERIFIED because boots wedge before mutter reaches the DRM phase (see blocker).

## THE BLOCKER (next focus): intermittent userspace hang during greeter launch
- 6 of 7 recent boots WEDGE at random timestamps (18/134/140/144/224/227s), during gdm
  greeter-session setup: gdm spawns /usr/bin/sh helpers, wait4-reaps, logind re-opens card0,
  `[B288 dgram /run/systemd/notify pidN] FDSTORE=1` loops — and **gnome-shell NEVER execs**
  (0 elf-loads of it). One boot (with debug-futextrace) DID get through to gnome-shell + DRM
  ioctls → it's timing-dependent, not a hard block.
- Signature = intermittent lost-wakeup / scheduler / SIGCHLD-wait4 / futex race under heavy
  fork/exec/wait churn. Note: `[wait4 reap]` logged the SAME tid multiple times in one run — look
  at SIGCHLD delivery + wait4/reaping + futex wake races first.
- Tooling hit walls: KVM gdb `qemu_interrupt` won't stop the CPU; no serial getty (image runs
  getty on tty0, not ttyS0); kernel **ignores `init=` cmdline** (hardcodes /init in
  smoke/src/elf.rs:95 — a real Linux-compat gap; honoring init= needs cmdline dep + init_path()
  parser, gated target_os=oxide-kernel to not break smoke's hosted build).

## Pick up here
1. Get a deterministic repro of the hang: hosted stress harness over fork/exec/wait4/SIGCHLD/futex
   (heavy churn like gdm), OR fix `init=` honoring to boot `init=/bin/bash` for a serial root shell
   to inspect a live hang + verify the virtgpu fix at the DRM level (open card0, VIRTGPU_GETPARAM).
2. Once a boot reaches mutter's DRM phase, confirm GETPARAM→GETRESOURCES→SETCRTC→scanout renders
   the greeter (screen capture via qemu_screen; framebuffer currently shows the text console).
3. First boot command: `make kernel boot` won't apply — use the MCP: qemu_start arch=x86_64
   accel=kvm mem=4G features=debug-boot, then qemu_run_until on the SETCRTC req
   `req=00000000c06864a2`; grep [DRMIOCTL] to map the mutter DRM sequence.
