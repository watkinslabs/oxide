# 51 Userspace handoff (kernel → init → getty → login → shell)

DRAFT (living). Dep:`16`,`19`,`28`,`29`,`29a`,`31`. Provides:concrete kernel→shell boot chain.

## 1 Purpose

`29` defines the abstract init/userspace contract. This doc nails the
concrete v1 path from kernel exit to a `~ #` prompt using **upstream
binaries only** — busybox 1.37 today, GNU coreutils + bash later.

Distilled rule: the kernel and image are ours; every program that
runs in user mode is upstream. Glue (config files, scripts, the
filesystem skeleton) is ours but is plain text, not C.

## 2 Invariants (frozen)

1. PID 1 binary on disk is `/sbin/init` — a hardlink to
   `/bin/busybox`. The kernel does not embed any compiled-in init
   blob in v1 once the rootfs path is mandatory.
2. Kernel spawns PID 1 with `argv[0]="/sbin/init"`, `envp=[]`,
   `fd 0/1/2 = /dev/console`, FS_BASE/TPIDR_EL0 = 0. Linux exec
   semantics — user crt1 sets up TLS.
3. busybox `init` reads `/etc/inittab`. v1 inittab format:
   `<id>:<runlevels>:<action>:<process>` per Linux sysvinit(5).
4. `/etc/init.d/rcS` is the sysinit shell script. Owned by us
   (text in `tools/xtask/etc/init.d/rcS`). It mounts proc/sys/tmp
   /run/dev/shm/devpts, sets hostname, brings up `lo`.
5. `/etc/init.d/oxide-smokes` (also ours, optional) runs the
   kernel-acceptance binaries from the rootfs. Replaces the C
   harness in the deleted `userspace/init/init.c`. Gated by
   presence of `/etc/oxide-init-smokes`.
6. getty is busybox `getty` (hardlink at `/sbin/getty`). Per
   inittab, respawned per VT.
7. Shell-of-record from `/etc/passwd` field 7. v1 = `/bin/sh`
   (busybox-ash); v1.x = `/bin/bash` (F154).
8. Every program in `/bin` and `/sbin` is either a hardlink to
   `/bin/busybox` or a kernel-acceptance smoke binary built from
   `userspace/<smoke>/`.

## 3 Boot chain (literal sequence, both arches)

| Step | Actor | Action |
|---|---|---|
| 1 | bootloader | Load kernel + `kernel/blobs/rootfs-<arch>.img` |
| 2 | kernel | mount ext4, find `/sbin/init` |
| 3 | kernel | exec `/sbin/init` argv0=`/sbin/init` env=`{}` fds=console |
| 4 | busybox init | open `/etc/inittab` |
| 5 | busybox init | run `::sysinit:/etc/init.d/rcS` synchronously |
| 6 | rcS | `mount -t proc proc /proc` |
| 7 | rcS | `mount -t sysfs sysfs /sys` |
| 8 | rcS | `mount -t tmpfs tmpfs /tmp` |
| 9 | rcS | `mount -t devpts devpts /dev/pts` |
| 10 | rcS | `hostname -F /etc/hostname` |
| 11 | rcS | `ifconfig lo 127.0.0.1 up` |
| 12 | rcS | run `/etc/init.d/oxide-smokes` if marker present |
| 13 | busybox init | for each `tty*::respawn:` → fork+exec `/sbin/getty` |
| 14 | getty | `setsid()`, open `/dev/tty1`, `ioctl(TIOCSCTTY)`, `setpgid(0,0)`, `tcsetpgrp(0,getpgrp())` |
| 15 | getty | print `/etc/issue`, read `login:` |
| 16 | getty | exec `/bin/login <user>` |
| 17 | login | match `/etc/passwd` + `/etc/shadow` |
| 18 | login | `setuid/setgid/setgroups`, env from `/etc/profile`, exec passwd-field-7 |
| 19 | shell | print prompt |

## 4 Filesystem skeleton (rootfs ext4)

```
/                          ext4 root
├── bin/                   busybox + applet hardlinks
├── sbin/                  busybox hardlinks (init, getty, login, halt, reboot)
├── lib/                   ld-musl-<arch>.so.1
├── lib64 -> lib           symlink
├── etc/
│   ├── passwd group shadow
│   ├── hostname os-release issue
│   ├── inittab
│   ├── fstab
│   ├── profile
│   ├── nsswitch.conf
│   └── init.d/
│       ├── rcS                        (sysinit)
│       └── oxide-smokes               (optional)
├── proc/                  empty mount point
├── sys/                   empty mount point
├── tmp/                   empty (tmpfs mounted by rcS)
├── dev/
│   ├── pts/               mount point for devpts
│   └── shm/               kernel pre-mounts tmpfs
├── run/                   kernel pre-mounts tmpfs
├── var/log/               regular dir
├── home/<user>/           per-user homes
└── root/                  root's home
```

## 5 /etc files (canonical contents staged by xtask)

### 5.1 /etc/inittab

```
::sysinit:/etc/init.d/rcS
::ctrlaltdel:/sbin/reboot
::shutdown:/bin/umount -a -r
tty1::respawn:/sbin/getty -L 38400 tty1 vt100
tty2::respawn:/sbin/getty -L 38400 tty2 vt100
```

### 5.2 /etc/init.d/rcS

```sh
#!/bin/sh
mount -t proc  proc  /proc
mount -t sysfs sysfs /sys
mount -t tmpfs tmpfs /tmp
mount -t devpts devpts /dev/pts
hostname -F /etc/hostname
ifconfig lo 127.0.0.1 up || true
[ -x /etc/init.d/oxide-smokes ] && /etc/init.d/oxide-smokes
:
```

### 5.3 /etc/init.d/oxide-smokes (gated by /etc/oxide-init-smokes)

```sh
#!/bin/sh
[ -e /etc/oxide-init-smokes ] || exit 0
echo "init-fork-exec works"
for s in /bin/bare3 /bin/sem_smoke /bin/msg_smoke /bin/mq_smoke \
         /bin/ptrace_smoke /bin/ptrace_singlestep_smoke \
         /bin/mprotect_smoke /bin/hello_dyn ; do
    [ -x "$s" ] && "$s"
done
```

### 5.4 /etc/profile

```sh
export PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
export PS1='\h:\w\$ '
export TERM=linux
```

### 5.5 /etc/fstab (informational, for `mount -a`)

```
proc    /proc    proc    defaults  0 0
sysfs   /sys     sysfs   defaults  0 0
tmpfs   /tmp     tmpfs   defaults  0 0
devpts  /dev/pts devpts  defaults  0 0
```

### 5.6 /etc/nsswitch.conf

```
passwd:  files
group:   files
shadow:  files
hosts:   files
```

## 6 Kernel surface required (must work before F153-3 verify)

| Need | Status today | Gate |
|---|---|---|
| ext4 read of `/sbin/init` | works | — |
| `execve` with argv set on user stack | works | — |
| `/dev/console` fd 0/1/2 inherited by PID 1 | works | — |
| `mount(2)` for `tmpfs` | works | — |
| `mount(2)` for `proc`/`sysfs`/`devpts` | admit-noop (kernel auto-registers) | rcS calls succeed |
| `/dev/tty1..N` inodes in devfs | works (`dev_console::register_all_vts`) | getty opens |
| `setsid`/`setpgid`/`TIOCSCTTY`/`TIOCSPGRP` | wired | getty's `setsid+TIOCSCTTY` returns 0 |
| `lo` interface for `ifconfig lo 127.0.0.1` | partial | rcS line tolerates `\|\| true` |
| `getrandom`/`/dev/urandom` for login PRNG | works | — |

## 7 What v1 does NOT do (deferred, named here so they don't surprise)

1. systemd, runit, s6 — only busybox-init.
2. PAM — busybox-login does its own crypt match; no PAM stack.
3. /etc/securetty enforcement — accepted-as-noop on busybox-login.
4. udev — busybox `mdev` only if rcS calls it. v1 has all needed
   nodes wired statically by the kernel at boot, so mdev is
   optional polish.
5. systemd-networkd, NetworkManager — `ifconfig lo` from rcS.
6. dbus, sd-bus — not started.

## 8 Phases / PR ladder

| PR | Scope |
|---|---|
| D51 (this doc) | freeze this spec — no code |
| F153-1 | delete `userspace/init/`, kernel/blobs/init.elf, INIT_REAL_BLOB; xtask hardlinks busybox at /sbin/init etc.; kernel passes argv0=/sbin/init |
| F153-2 | xtask emits /etc/inittab, /etc/init.d/{rcS,oxide-smokes}, /etc/profile, /etc/fstab, /etc/nsswitch.conf; empty mount-point dirs |
| F153-3 | end-to-end: type `root` at login → `~ #`. Whatever doesn't work → kernel patch in same PR |
| F154 | cross-build bash 5.2; flip /etc/passwd shells |
| F155 | cross-build GNU coreutils; stage at /usr/bin |

## 9 Test contract

| Acceptance gate | Method |
|---|---|
| busybox init banner | `make qemu-x86` and `make qemu-arm` both print init banner |
| rcS mounts succeed | `cat /proc/mounts` from interactive shell shows proc/sys/tmp/devpts |
| getty respawns | kill the shell, getty re-opens login on same tty |
| login → shell | type `root` + Enter → `~ #` prompt |
| smokes path optional | `OXIDE_INIT_SMOKES=0 make qemu-x86` reaches login without smoke output |
| `OXIDE_INIT_SMOKES` default | smokes run before login banner |

## 10 Cross-references

- `29§3` — abstract init contract
- `29a§2` — userspace target triple (musl-static-pie convention)
- `28§3` — VT/console semantics getty depends on
- `19` — devfs/procfs/sysfs registration paths
- `16` revisions R01/R02 — mount(2) namespace + dirent hooks
- `31§4` — ELF loader stack/auxv
