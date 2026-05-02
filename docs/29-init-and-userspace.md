# 29 Init + Userspace bring-up

Status: DRAFT 2026-05-02
Depends on: `01`,`02`,`13`,`15`,`16`,`19`,`28`,`31`,`39`.
Provides to: every running userspace.

## 1 Purpose

PID 1 (init), libc, image build pipeline (initramfs + on-disk root), boot-to-shell sequence.

## 2 Invariants (frozen)

1. Kernel exec's `/init` (or `/sbin/init` fallback) as PID 1 from initramfs.
2. PID 1: signal-default-ignore for many; reaps orphans; exit ⇒ kernel panic.
3. Initramfs is a CPIO archive (gzip or zstd) loaded by bootloader, mounted as initial rootfs (tmpfs-backed).
4. Real root mounted via `pivot_root` from initramfs once block devices come up.
5. libc (musl, vendored fork) ships with our syscall stubs and dynamic linker `/lib/ld-oxide.so.1`.

## 3 Init (PID 1)

Minimal init for v1: a 200-line Rust program at `userspace/init/`. Responsibilities:
1. Mount `/proc`, `/sys`, `/dev` (devtmpfs), `/dev/pts` (devpts), `/sys/fs/cgroup` (cgroup2).
2. Read `/etc/init.conf` (TOML): list of services with `cmd`, `restart=on-failure|always|never`.
3. Spawn each service.
4. Reap zombies forever (loop on `waitid`).
5. Handle SIGTERM/SIGINT/SIGUSR1: shutdown.
6. Handle child exit per restart policy.

Not systemd. Not OpenRC. v1.x can ship something fancier (sd_notify, socket-activation). v1: just enough to launch a shell.

## 4 libc

Vendored fork of musl at `userspace/libc/musl/`. Patches:
- Syscall stubs in `arch/x86_64/syscall_arch.h`,`arch/aarch64/syscall_arch.h` use our trap instructions (same Linux opcodes).
- Define `__OXIDE__` macro for any oxide-specific code paths (none expected; goal is unmodified upstream behavior).
- vDSO lookup via auxv `AT_SYSINFO_EHDR`.
- Dynamic linker installed at `/lib/ld-oxide.so.1` (ELF interp path).

## 5 Image pipeline

`xtask image --arch <a>` produces `boot.img`:
1. ESP partition: `EFI/BOOT/BOOTX64.EFI` (or `BOOTAA64.EFI`) ← Limine (x86) / EDK2-compatible loader.
2. Kernel ELF.
3. Initramfs.cpio.zst.
4. Bootloader config (`limine.conf` / device-tree blob with kernel args).
5. (Optional) extra rootfs partition with ext4.

`xtask user --arch <a>` builds userspace:
- All of `userspace/coreutils-{ls,cat,cp,...}`, `userspace/sh` (busybox-equivalent or actual busybox built against our libc), `userspace/init`.
- Statically linked or against our libc.
- Stripped, packed into cpio.

`xtask qemu --arch <a>` runs:
- `qemu-system-<arch> -bios /usr/share/edk2/<arch>/code.fd -drive ...boot.img -smp 4 -m 4G -nographic`.

## 6 Boot sequence (post-kernel-init)

1. Kernel mounts initramfs at `/`.
2. Kernel exec's `/init` (which is our `init` binary).
3. `init` does §3 sequence.
4. `init` spawns `getty` on `/dev/tty1`,`/dev/ttyS0` (per config).
5. `getty` reads username, exec's `/bin/login`.
6. `login` authenticates against `/etc/passwd`+`/etc/shadow` (Argon2id), exec's user shell.
7. User's `bash` runs.

For headless server: skip getty/login, init exec's a configured service.

## 7 /etc baseline

Initramfs `/etc/`:
- `passwd`,`shadow`,`group`: minimal (root + service accounts).
- `nsswitch.conf`: `files dns`.
- `resolv.conf`: nameservers (or DHCP-populated post-boot).
- `hosts`: `127.0.0.1 localhost`.
- `init.conf`: services list.
- `os-release`: distro identity.
- `fstab`: mount points (parsed by init for non-essential mounts).
- `localtime` symlink.

## 8 Concurrency

Init is single-threaded. Reaps via `waitid(P_ALL, WEXITED|WNOHANG, &si)` in a SIGCHLD-driven loop.

## 9 Perf budget

| Phase | wall-clock |
|---|---|
| Bootloader → kernel start | ≤ 1 s |
| Kernel start → exec(init) | ≤ 500 ms |
| init → first shell prompt | ≤ 1 s |

## 10 Test contract (frozen)

- `xtask qemu` boots to a shell prompt within 3s of bootloader handoff.
- `init` reaps orphan zombies (test harness fork+abandon).
- `init` exit ⇒ kernel panic with "init exited" message.
- Service restart on failure: kill a service, verify restart per policy.
- Mount sequence: every mount in `init.conf` succeeds before service spawn.
- Acceptance: run `busybox sh -c "ls /; cat /proc/cpuinfo; uptime"` from boot; output matches expected substrings.

## 11 Failure modes

- `/init` not found in initramfs: kernel panic.
- `/init` exits with status: kernel panic.
- Mount in `init.conf` fails: log, continue (init does not fail on mount errors except for `/proc`,`/sys`,`/dev`).

## 12 Debug

`debug-init`: trace every fork+exec; full env dump.

## 13 Cross-spec

`13`+`15` (clone3,execve), `16`+`19` (mounts), `28` (controlling tty for getty), `31` (ELF loader for execve), `39` (image builder).

## 14 Open Questions

- systemd as PID 1 in v1.x or v2? v2.
- OpenRC vs custom init: stick with custom for v1 (minimal); accept that "service" is reserved.
- musl vs glibc as primary libc: musl.
- Static vs dynamic for v1 binaries: static (simpler boot; no dynlink bring-up); dynlink validated via a single test binary.
