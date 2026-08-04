# 29 Init + Userspace bring-up

FROZEN 2026-05-02. Dep:`01`,`02`,`13`,`15`,`16`,`19`,`28`,`31`,`39`,`51`. Provides:every running userspace.

## 1 Purpose

PID 1 (init), libc, ext4 root-image pipeline, boot-to-shell sequence.

## 2 Invariants (frozen)

1. Kernel mounts the ext4 root disk and exec's `/sbin/init` as PID 1.
2. PID 1: signal-default-ignore for many; reaps orphans; exit ⇒ kernel panic.
3. Root filesystem is an ext4 disk assembled by `../images`, attached as virtio-blk, and mounted directly as `/`.
4. libc + loader are upstream Fedora glibc (`libc.so.6`, `ld-linux-x86-64.so.2` / `ld-linux-aarch64.so.1`) installed from RPMs; this repo builds neither.

## 3 Init (PID 1)

PID 1 is upstream systemd from the Fedora rootfs, reached via `/sbin/init`. Literal chain, unit tree, and `/etc` glue in `51§2-3`. No init binary is built here.

Kernel obligations toward PID 1: exec `/sbin/init` with `argv[0]="/sbin/init"`, fds 0/1/2 on `/dev/console`, zero TLS base (`51§2`); panic if it exits (§2 invariant 2).

## 4 libc (consumed, not built)

Upstream Fedora glibc, installed from RPMs into the rootfs by `../images`:
- `libc.so.6` + the `GLIBC_2.x` symbol-version set Fedora ships.
- Loader `/lib64/ld-linux-x86-64.so.2` (x86_64) / `/lib/ld-linux-aarch64.so.1` (aarch64), named by `PT_INTERP` in every dynamic binary (`31§5`).
- vDSO located via auxv `AT_SYSINFO_EHDR` (`15§8`).

The kernel's obligation is the Linux syscall ABI in `15`; glibc is unmodified, so any divergence is a kernel bug, never a libc patch.

### 4.1 Image order

| Step | Artifact | Source | Consumes |
|---|---|---|---|
| 1 | kernel ELF | `xtask kernel` → `xtask artifacts` | `07§3.4` |
| 2 | rootfs image | `../images` composes + packs `<profile>-<arch>-root.img` from RPMs | Fedora + local oxide RPMs |
| 3 | boot disk | `xtask rootfs` copies step 2; `xtask image`/`grub` joins step 1 | steps 1 + 2 |

Kernel binary is independent of step 2. Composition (package set, `/etc` contents, users) is owned by `../images`, not by this repo.

## 5 Image pipeline

`xtask image --arch <a>` produces `target/builds/<ns>/oxide-<arch>-grub.iso` (`39§5`):
1. `boot/grub/grub.cfg` — `multiboot2` (x86_64) or `linux` (aarch64) menuentry with the kernel cmdline.
2. `boot/oxide-x86_64` (kernel ELF) or `boot/oxide-aarch64.Image` (EFI-stub arm64 Image).
3. `grub2-mkrescue` wraps both into a bootable ISO — BIOS El Torito on x86_64, EFI (vendored `arm64-efi` modules) on aarch64.

Root is a separate ext4 disk (`root-<arch>.img`, virtio-blk), not part of the ISO. No initramfs.

`xtask rootfs --arch <a>` supplies the root filesystem: copy of `../images/output/<profile>-<arch>-root.img`, already composed + packed from RPMs. No userspace build step exists in this repo.

`make qemu-x86` / `make qemu-arm` run the matching GRUB ISO plus root disk;
the smoke targets add the serial verdict harness.

## 6 Boot sequence (post-kernel-init)

1. Kernel mounts the ext4 root.
2. Kernel exec's `/sbin/init` (systemd).
3. systemd runs its unit tree (`51§3`).
4. systemd spawns `agetty` per VT unit.
5. `agetty` reads username, exec's `/bin/login`.
6. `login` authenticates via PAM against `/etc/passwd`+`/etc/shadow`, exec's the shell from passwd field 7.
7. User's `bash` runs.

For headless server: no getty unit; systemd runs the configured service.

## 7 /etc baseline

Staged into the rootfs by `../images`, not by this repo:
- `passwd`,`shadow`,`group`: root + service accounts.
- `nsswitch.conf`: `files dns`.
- `resolv.conf`: nameservers (or DHCP-populated post-boot).
- `hosts`: `127.0.0.1 localhost`.
- `systemd/`: unit tree (`51§2`).
- `os-release`: distro identity.
- `fstab`: mount points.
- `localtime` symlink.

## 8 Concurrency

systemd reaps orphans via `waitid(P_ALL, WEXITED|WNOHANG, &si)` in a SIGCHLD-driven loop; the kernel's obligation is reparent-to-PID-1 plus SIGCHLD delivery (`13`).

## 9 Perf budget

| Phase | wall-clock |
|---|---|
| Bootloader → kernel start | ≤ 1 s |
| Kernel start → exec(init) | ≤ 500 ms |
| init → first shell prompt | ≤ 1 s |

## 10 Test contract (frozen)

- `make smoke-x86` and `make smoke-arm` boot the Fedora rootfs to `oxide login:`.
- PID 1 reaps orphan zombies (test harness fork+abandon).
- PID 1 exit ⇒ kernel panic with "init exited" message.
- systemd restarts a killed service per its unit `Restart=` policy.
- Early-boot mount units succeed before the services depending on them start.
- Acceptance: run `bash -c "ls /; cat /proc/cpuinfo; uptime"` from boot; output matches expected substrings.

## 11 Failure modes

- `/sbin/init` not found in the root filesystem: kernel panic.
- `/sbin/init` exits with status: kernel panic.
- A mount unit fails: systemd policy (`51§3`); the kernel reports the errno and continues.

## 12 Debug

`debug-init`: trace every fork+exec; full env dump.

## 13 Cross-spec

`13`+`15` (clone3,execve), `16`+`19` (mounts), `28` (controlling tty for getty), `31` (ELF loader for execve), `39` (image builder).
