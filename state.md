# state.md — session handoff

## Headline
**GNOME boot campaign: the EXIT_NAMESPACE(226) cascade that blocked every sandboxed systemd service is ELIMINATED.** Two fixes merged to `origin/main` (PR #2311, #2312). live-gnome boot now reaches getty.target, gdm launches, graphical.target is queued. Both arches smoke to login. **Next blocker: gdm launches but exits (code 265/271) — graphical.target not yet reached.**

## What got done (merged, boot-verified)
- **PR #2311** `fix(mount): mount_setattr AT_EMPTY_PATH + mount-aware bind target` (SHA f6748b62). Killed the *deterministic* domainname `-EBUSY` (systemd `bind_remount_recursive`'s 32-retry cap). Six root causes, all Linux divergences: (1) `mount_setattr(fd,"",AT_EMPTY_PATH,{RDONLY})` on a detached fsmount object ignored → now folds into atomic `MountObjectInode.mnt_attrs` / stamps the detached clone tree; (2) attached `mount_setattr` ignored dirfd+AT_EMPTY_PATH → `resolve_at_lookup`; (3) support-probe returned EFAULT not EINVAL (validation reorder); (4) `canonical_mount_path` mount-UNAWARE (`dentry.absolute_path()` drops bind prefix on shared dentries) → mount-aware reconstruction; (5) `attach`/commit_tree rendered via `abs_string` → new `rendered_path_for()` walks the mount tree; (6) bind on a SHARED target dentry hashed under wrong parent → new `register_bind_under()` attaches under the resolved target mount (Linux `do_add_mount` keys on `struct path`).
- **PR #2312** `fix(open): O_PATH must not invoke the device driver open` (Linux FMODE_PATH). `on_open()` was called unconditionally in `002_open.rs`/`257_openat.rs`; gated on `!O_PATH`. Fixed the residual *concurrency* 226: ProtectKernelLogs overmounts /dev/kmsg with the inaccessible `devt 0:0` char; systemd `mount_entry_chase` O_PATH-opens every target → `lookup_chrdev(0:0)` ENXIO → 226. Now 0/3 boots.

## Verified
226 = 0 across 3 sequential live-gnome boots (was 13–105). `make smoke-x86` login 28s, `make smoke-arm` login 14s. Both arches build release. vfs hosted tests green.

## Open / next blocker: gdm
gdm (`/usr/bin/gdm`) launches during graphical.target startup but the fork-child exits (kernel `[EXIT]` trace: `exe=/usr/bin/gdm code=265` and `code=271`). graphical.target queued, not reached. Investigate: boot live-gnome, capture gdm's `[EXIT]` recent-syscall ring + why it exits. gdm needs: DRM (/dev/dri/card0 via virtio-gpu), Xorg/wayland, logind seat0, dbus. Likely a missing device/DRM/KMS path or a gdm dependency. Method that worked this session: kernel klog `[TAG]` traces at the exact failing syscall/return, correlate counts 1:1 with the failure, disprove-don't-hack.

## Boot / diagnosis notes (this session)
- **Diagnostic cmdline** lives in `../oxide-images/imagectl/src/main.rs` line ~963 (GRUB menuentry, NOT git-tracked). Default `quiet`. For systemd errors on serial without journald: `systemd.log_target=kmsg systemd.journald.forward_to_console=1` (kmsg is SLOW → serializes the race; can hide concurrency bugs). `systemd.log_target=console` avoids /dev/kmsg but systemd child errors still may not reach serial. **Restore to `quiet` when done.**
- Boot loop: `cd ../oxide-images && make kernel ARCH=x86_64 && make boot PROFILE=live-gnome ARCH=x86_64 && bash oneboot.sh output/x.log <secs>`. `make kernel` = xtask kernel + xtask artifacts (real). A real boot is >2000 lines; ~1400 or 8 lines = GRUB-partial, re-run.
- Kernel `[EXIT]` watchdog prints `exe=` + `code=` + a recent-syscall ring (newest first) for every process exit — the ring's last non-zero-return syscall is the smoking gun. `code=226` = systemd EXIT_NAMESPACE.
- Bash sandbox can't kill qemu; use `pkill -9 -f qemu-system-aarch64` with `dangerouslyDisableSandbox: true`. A stale qemu blocks the next boot (port/resource) → "qemu-arm Error 1".

## First task next session
`git checkout main && git pull`. Boot live-gnome (quiet), find gdm's `[EXIT]` block + recent-syscall ring, identify the failing op (DRM/dbus/seat/wayland), fix to match Linux. Keep going through the graphical-target dependency chain until GNOME runs (active `/goal`: fix all errors preventing gnome from booting).
