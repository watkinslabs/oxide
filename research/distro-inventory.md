# oxide2 userspace / distro inventory

Snapshot 2026-05-29, branch `F264-vendor-systemd` (D-roadmap mid-flight, pre-systemd).
Read-only audit. Source of truth: `tools/xtask/src/main.rs` (`cmd_rootfs`, lines 40–867),
the boot-smoke scripts, the Makefile, `state.md`, and the `vendor/` tree.

> All version strings below are confirmed from `VERSION=` lines in `tools/fetch-*.sh`.

---

## 1. Boot / init chain

### PID 1
**PID 1 is busybox `init`**, served as a debugfs hardlink to `/bin/busybox`:
- `xtask/src/main.rs:278-293` hardlinks `/sbin/init`, `/init`, plus `halt/reboot/poweroff/shutdown/mdev` to `/bin/busybox`.
- `xtask/src/main.rs:183-185`: "no embedded init blob. PID 1 lives in the rootfs as a `/sbin/init` busybox hardlink; the kernel reads it from ext4 at boot."
- The kernel boot path probes `/sbin/init` then `/init` (comment line 291).

### inittab (`/etc/inittab`, staged lines 646-652)
```
::sysinit:/etc/init.d/rcS
::ctrlaltdel:/sbin/reboot
::shutdown:/bin/umount -a -r
ttyS0::respawn:/sbin/getty -L 115200 ttyS0 vt100
```
- sysinit runs `rcS`; serial console `ttyS0` respawns `/sbin/getty` (busybox getty → `/sbin/agetty` is util-linux, but `/sbin/getty` is a debugfs symlink to `/sbin/agetty` per line 377; busybox also provides `getty`/`agetty` applets, and util-linux agetty is staged at `/sbin/agetty`).
- `getty` → `login`. `/bin/login` is **util-linux login** (D1, line 360-362), with busybox login as fallback applet.

### getty / login / agetty
- `/sbin/agetty` = util-linux agetty (line 361). `/sbin/getty` symlink → agetty (line 377).
- `/bin/login` and `/usr/bin/login` = util-linux login (lines 360, 378).
- `/bin/su`, `/usr/bin/su` = util-linux su (lines 364, 379).

### rcS (`/etc/init.d/rcS`, staged lines 672-718) — quoted verbatim
```sh
#!/bin/sh
mount -t proc  proc  /proc 2>/dev/null
mount -t sysfs sysfs /sys  2>/dev/null
mount -t tmpfs tmpfs /tmp  2>/dev/null
mount -t tmpfs tmpfs /var/run 2>/dev/null
mount -t tmpfs tmpfs /var/db  2>/dev/null
mount -t devpts devpts /dev/pts 2>/dev/null
hostname -F /etc/hostname 2>/dev/null
ifconfig lo 127.0.0.1 up 2>/dev/null
ifconfig eth0 up 2>/dev/null
# F141: udhcpc is the v1 DHCP client (busybox applet ...)
if [ -e /etc/oxide-udhcpc-enable ] && [ -x /sbin/udhcpc ]; then
    /sbin/udhcpc -i eth0 -s /usr/share/udhcpc/default.script -q -n -t 3 -T 2
    [ -x /bin/online_smoke ] && /bin/online_smoke
    [ -x /bin/tcp_smoke ]    && /bin/tcp_smoke
fi
[ -x /etc/init.d/oxide-smokes ] && /etc/init.d/oxide-smokes
# F210: openssh sshd (port 22). Generates host keys on first boot ...
if [ -x /usr/sbin/sshd ]; then
    echo sshd-step-pre-keygen
    if [ ! -f /etc/ssh/ssh_host_ed25519_key ]; then
        /usr/bin/ssh-keygen -t ed25519 -N '' -f /etc/ssh/ssh_host_ed25519_key 2>&1
        echo ssh-keygen-rv=$?
    fi
    echo sshd-step-post-keygen
    ls -l /etc/ssh/ 2>&1
    ifconfig eth0 10.0.2.15 netmask 255.255.255.0 up 2>/dev/null
    route add default gw 10.0.2.2 2>/dev/null
    echo sshd-step-launch
    /usr/sbin/sshd -D -e 2>&1 &
    echo sshd-step-launched-bg pid=$!
fi
:
```

### Where the rootfs is assembled
`tools/xtask/src/main.rs` → `cmd_rootfs(--arch x86_64|aarch64)` (Makefile targets `rootfs-x86`/`rootfs-arm`). Mechanism:
1. Compile C smoke/probe binaries + PAM modules via `musl-gcc` (x86) or `vendor/cross/aarch64-linux-musl-cross` (arm) into `target/userspace-<arch>/` (lines 67-181).
2. `dd` a **32 MiB** zero file → `mkfs.ext4 -b 4096 -O ^has_journal -L oxide` → `kernel/blobs/rootfs-<arch>.img` (lines 188-203).
3. Populate via `debugfs -w -R` (one command per invocation): `mkdir` the FHS tree, `write` files, `ln` hardlinks, `sif … mode` for perms (lines 205-861).

### FHS layout created (lines 216-228)
```
/bin /sbin /lib /lib64
/etc /etc/init.d
/proc /sys /tmp /run
/dev /dev/pts
/home /home/alice /root
/var /var/log /var/db /var/db/dhcpcd /var/run /var/run/dhcpcd
/usr /usr/share /usr/share/keymaps /usr/share/udhcpc
/usr/bin /usr/sbin /usr/libexec
/usr/lib /usr/lib/security
/usr/share/terminfo/{d,l,s,v,x}
/etc/ssh  /etc/pam.d  /var/empty   (created later, conditional on sshd/pam staging)
```

---

## 2. Vendor inventory

Every dir under `vendor/`. Real distro programs are cross-built static-musl per-arch
(suffixed `-x86_64` / `-aarch64`); busybox is a single multi-call binary per arch.

| vendor dir | program(s) | version | role |
|---|---|---|---|
| `busybox` | busybox multi-call (`busybox`, `busybox-aarch64`) | 1.37.0 | **fallback for ~all base utils + init/getty/mount/networking applets** |
| `bash` | bash | 5.2.37 (F216) | **`/bin/sh` AND `/bin/bash`** (busybox ash/hush dropped from /bin/sh) |
| `coreutils` | coreutils single-binary | 8.32 (F218) | ls,cat,cp,… (~80 applets at /usr/bin, ahead of busybox in PATH) |
| `util-linux` | login,agetty,su,kill,cal,losetup,mount,umount | 2.40.2 (D1) | login/getty/su; mount/umount staged as `.util-linux` only (non-PIE, not active) |
| `shadow` | useradd,userdel,usermod,group*,passwd,chage,gpasswd,newgrp,chgpasswd | 4.16.0 (D2) | account management |
| `procps-ng` | ps,top,free,vmstat,uptime,pgrep,pkill,pmap,tload,w,watch,slabtop,sysctl | 4.0.5 (D3) | process/proc tools |
| `iproute2` | ip,ss,tc,bridge,rtmon,lnstat,nstat,ifstat | 6.10.0 (D4) | modern net config (`ip` → also `/bin/ip`) |
| `iputils` | ping,tracepath,clockdiff,arping | 20240117 (D5) | ICMP tools (**runtime ICMP not yet exercised — see §9**) |
| `openssh` | sshd, sshd-session, ssh-keygen, ssh | 9.9p2 | real SSH server+client (no OpenSSL → ed25519 only) |
| `dropbear` | dropbear | 2024.86 | **superseded by openssh; not staged in rootfs** (legacy) |
| `vim` | vim | 9.1.0950 (F251) | editor, links ncurses |
| `less` | less | 643 (F254) | pager |
| `nano` | nano | 8.5 | editor (**vendored, source only — NOT built/staged in xtask — see §9**) |
| `sed` | GNU sed | 4.9 (F217) | /usr/bin/sed ahead of busybox |
| `grep` | GNU grep | 3.11 (F219) | /usr/bin/grep |
| `gawk` | GNU gawk | 5.3.1 (F222) | /usr/bin/gawk + awk |
| `tar` | GNU tar | 1.35 (F220) | /usr/bin/tar |
| `make` | GNU make | 4.4.1 (F221) | /usr/bin/make |
| `patch` | GNU patch | 2.7.6 (F225) | /usr/bin/patch |
| `findutils` | find, xargs | 4.10.0 (F223) | /usr/bin/find,xargs |
| `diffutils` | diff, cmp | 3.10 (F224) | /usr/bin/diff,cmp |
| `gzip` | gzip (`gzip-{x86_64,aarch64}` built) | 1.13 | **built but NOT staged in xtask** (busybox gzip used) |
| `bzip2` | bzip2 | 1.0.8 (F226) | /usr/bin/bzip2 |
| `xz` | xz | 5.6.3 (F227) | /usr/bin/xz |
| `zlib` | libz (install-{x86_64,aarch64} tree) | 1.3.1 | build dep for ssh/others (static .a) |
| `ncurses` | libncurses (install tree) + terminfo | 6.5 (F252) | build dep for vim/less; terminfo db |
| `pam` | libpam + headers (1.5.3 + 1.7.2 both present) | 1.7.2 (F231/F239) | linked by sshd; modules in /usr/lib/security |
| `dhcpcd` | dhcpcd | 10.3.2 (F123) | /sbin/dhcpcd (**auto-launch gated off — crashes, see §9**) |
| `musl` | ld-musl-<arch>.so.1 (prebuilt .so, no fetch script) | musl 1.2.x | dynamic loader (ld-musl-x86_64.so.1 + ld-musl-aarch64.so.1) |
| `cross` | aarch64-linux-musl-cross toolchain | (musl.cc) | build-time only |
| `limine` | Limine bootloader | (vendored) | x86_64 boot |
| `firmware` | firmware blobs | — | boot/device |

### busybox-vs-real command split

**Served by busybox hardlinks** (xtask lines 259-292) — note many are *shadowed* by a
real binary later in PATH (`/usr/bin` precedes `/bin`):
- `/bin`: ash, hush, ls, cat, echo, cp, mv, rm, mkdir, rmdir, dmesg, grep, egrep, fgrep, find, head, tail, wc, sort, uniq, touch, chmod, chown, ln, test, true, false, env, printf, yes, seq, expr, id, whoami, tr, cut, sed, awk, date, df, du, stat, sleep, tee, xxd, hostname, uname, pwd, basename, dirname, which, clear, reset, more, less, vi, tar, gzip, gunzip, ifconfig, route, ping, nc, wget, mknod, stty, tty, mesg
- `/sbin`: init, halt, reboot, poweroff, shutdown, mdev, ifconfig, route, fdisk, swapon, swapoff, **mount, umount**, udhcpc, udhcpd
- `/bin/mount`, `/bin/umount` (so rcS's `mount` resolves)

**Actually-used real programs win in PATH** (`/usr/bin`,`/usr/sbin` before `/bin`,`/sbin`):
ls/cat/cp/mv/rm/… (coreutils), sed (GNU), grep (GNU), find/xargs (GNU), awk (gawk),
tar/diff/cmp/patch/bzip2/xz/make, ps/top/free/… (procps), ip/ss/tc (iproute2),
ping (iputils — but busybox `/bin/ping` also present; iputils not staged to a winning
path here — *verify which ping wins*), vim, less.

**busybox-ONLY (no real replacement yet), genuinely used:**
- **PID 1 init**, halt/reboot/poweroff/shutdown
- **mount/umount** (util-linux mount is non-PIE → staged inert at `/usr/sbin/*.util-linux`)
- **ifconfig, route** (iproute2 `ip` exists but rcS still uses busybox ifconfig/route)
- **udhcpc/udhcpd** (the active DHCP client; dhcpcd disabled)
- mdev (device manager), fdisk, swapon/swapoff, nc, wget, dmesg, stty, mesg, vi (busybox vi alongside real vim)

---

## 3. musl / dynamic-linking state

- **Dynamic loader present:** `vendor/musl/ld-musl-<arch>.so.1` → staged at
  `/lib/ld-musl-x86_64.so.1` (or `…aarch64…`). On aarch64 also staged at `/lib/libc.so`
  because the ARM cross-gcc emits `DT_NEEDED=libc.so` (lines 312-328).
- **Almost everything is static-musl.** All vendored real programs are built `-static`
  per their `build.sh`; the smoke binaries are `musl-gcc -static -no-pie`.
- **Dynamic linking is exercised only by test binaries**, not the distro proper:
  - `/bin/hello_dyn` (-pie, nostdlib) — PT_INTERP test of ld-musl
  - `/bin/hello_dyn_libc` (default dynamic, links libc.so)
  - `dynlink` (-static-pie)
- **No real shared `/lib`/`/usr/lib`** of system libraries. `/usr/lib/security/` holds
  PAM modules as `.so` (pam_permit/pam_deny/pam_unix/pam_unix_stub), dlopened by libpam
  which is **statically linked into sshd** (DEFAULT_MODULE_PATH baked to `/usr/lib/security/`).
  zlib/ncurses/pam are linked statically into the consumers, not shipped as shared `.so`.
- Net: a production distro would replace static-everything with a real shared
  `/lib`+`/usr/lib` (libc.so, libz, libncurses, libpam, etc.) loaded by ld-musl.

---

## 4. Services / daemons

| daemon | binary | started by | status |
|---|---|---|---|
| **sshd** (openssh) | `/usr/sbin/sshd` (+ `/usr/libexec/sshd-session`) | rcS, `sshd -D -e &` after host-key gen | **working** — ssh-smoke logs in as alice via password, runs `id` (boot-smoke-ssh.sh) |
| **udhcpc** (busybox) | `/sbin/udhcpc` | rcS, gated on `/etc/oxide-udhcpc-enable` | opt-in; configures eth0 + writes /etc/resolv.conf via default.script |
| **dhcpcd** (real) | `/sbin/dhcpcd` | NOT auto-launched (B44 gate `OXIDE_DHCPCD_ENABLE`) | **broken** — userspace heap corruption post-lease; kernel survives the #GP now but dhcpcd still crashes |
| **getty/login** | agetty→login (util-linux) | inittab respawn on ttyS0 | working (serial console login) |

No syslogd/klogd, no cron, no dbus, no networkd/resolved, no systemd — that's D6 (next).

---

## 5. Test / smoke infrastructure

### Makefile targets
- `make smoke` = `smoke-x86` + `smoke-arm`; each builds kernel + rootfs then runs `tools/boot-smoke.sh <arch>`.
- `make qemu-x86`/`qemu-arm`, `kernel-*`, `rootfs-*`, `test` (hosted cargo tests), `spec-lint`/`accept`.

### `tools/boot-smoke.sh <arch>` (the pre-push gate)
Boots kernel under QEMU headless (x86 via Limine ISO from make-iso.sh; arm via `-kernel`),
polls serial up to TIMEOUT_SECS (default 90) for the literal banner **`oxide login:`**.
PASS = banner seen. This is the only mandatory gate; it validates the entire boot→init→rcS→getty
chain reaches a login prompt.

### `tools/boot-smoke-ssh.sh <arch>`
Adds `-netdev user,hostfwd=tcp::2222-:22` + virtio-net-pci + the rootfs as a virtio disk.
Waits for `oxide login:`, then `sshd-step-launched-bg`, then `sshpass -p swordfish ssh
alice@127.0.0.1 id` and asserts `uid=1000`. **End-to-end SSH login validated.**

### `tools/boot-smoke-dhcp.sh <arch>`
user-net + virtio-net; waits for `udhcpc: configured` line. Validates a DHCP lease + iface config.

### In-guest smoke harness `/etc/init.d/oxide-smokes` (staged lines 728-753)
Gated by `/etc/oxide-init-smokes` (skip with `OXIDE_INIT_SMOKES=0`). Runs:
`bare3, vim_smoke, sem_smoke, msg_smoke, mq_smoke, mprotect_smoke, mmap_zero_smoke,
usleep_smoke, af_packet_smoke, hello_dyn`, then `exit_test`, `bash --version`,
`pthread_socketpair_probe`, `socketpair_fork_probe`, `hello_dyn_libc`.
(ptrace_smoke/ptrace_singlestep_smoke staged but **excluded** from the harness — they hang
on a PTRACE_SINGLESTEP / SIGSTOP-SIGTRAP race, comment lines 723-727.)

These probe kernel ABI: SysV sem/msg, POSIX mq, mprotect, anon mmap, nanosleep,
AF_PACKET, dynamic loader, exit semantics, pthreads over socketpair, fork+socketpair.

### What's validated on boot, each arch
Both arches must reach `oxide login:` (lockstep gate). The in-guest harness exercises the
syscall/ABI surface above. SSH + DHCP have dedicated cross-arch smoke scripts.

---

## 6. Networking stack

- **In-kernel TCP/IP stack exists** (the `ip`, `ss`, ping, sshd, DHCP all rely on it; smoke
  binaries `tcp_smoke`, `online_smoke`, `af_packet_smoke` exercise it).
- **Interfaces:** `lo` (configured 127.0.0.1 in rcS) and `eth0` (virtio-net-pci in smoke
  harnesses). rcS brings both up.
- **Works:** TCP (sshd accepts real connections from the host, ssh-smoke passes);
  outbound DNS round-trip via slirp 10.0.2.3 (`online_smoke`); DHCP lease via **busybox
  udhcpc** (dhcp-smoke passes); AF_PACKET sockets.
- **Flaky / gaps:**
  - real **dhcpcd** crashes post-lease (userspace heap corruption) — udhcpc used instead.
  - iproute2 `ip link` → "EOF on netlink" on RTM_GETLINK dumps (kernel rtnetlink
    partial-reply bug, per state.md follow-ups).
  - iputils **ping ICMP runtime not yet exercised** (`ping -c1 127.0.0.1` never run).
- Static config in rcS hardcodes the slirp topology (eth0 10.0.2.15, gw 10.0.2.2).

---

## 7. /etc contents shipped (quoted)

- **`/etc/passwd`** (lines 591-595):
  ```
  root:x:0:0:root:/root:/bin/sh
  alice:x:1000:1000:Alice User:/home/alice:/bin/sh
  nobody:x:65534:65534:nobody:/:/bin/false
  ```
- **`/etc/group`** (596-601): `root:x:0:` / `wheel:x:10:alice` / `users:x:100:alice` / `nobody:x:65534:`
- **`/etc/shadow`** (605-609): root no password (`root::…`); alice = sha512crypt of "swordfish"
  (`$6$alsalt$…`); nobody locked (`!`). Comment: alice hash matches a v1 sha512crypt, to be
  regenerated at Drepper-2007 parity (P14-08).
- **`/etc/hostname`**: `oxide`
- **`/etc/os-release`**: `NAME=oxide / VERSION=0.1 / ID=oxide / PRETTY_NAME="oxide-os 0.1"`
- **`/etc/issue`**: `oxide \s on \l`
- **`/etc/fstab`** (820-826): proc, sysfs, tmpfs(/tmp), devpts — informational for `mount -a`.
- **`/etc/nsswitch.conf`** (829-835): `passwd/group/shadow/hosts: files` (files-only resolver).
- **`/etc/profile`**: PATH=`/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin`, PS1, `TERM=linux`.
- **`/etc/login.defs`**: ENV_PATH / ENV_SUPATH (so login seeds PATH before exec'ing shell).
- **`/root/.profile`**: root PATH + PS1.
- **`/etc/inittab`**: see §1.
- **`/etc/dhcpcd.conf`** (658-669): minimal, 10s timeout, no hooks.
- **`/etc/pam.d/sshd`** (630-637): `auth/account/password/session required pam_unix.so`.
- **`/etc/ssh/sshd_config`** (612-628): Port 22, inet only, ed25519 hostkey, PermitRootLogin no,
  PasswordAuthentication yes, UsePAM yes, no DNS/motd/lastlog, StrictModes no.
- **No `/etc/resolv.conf` shipped** — written at runtime by udhcpc's default.script.
- Markers: `/etc/oxide-init-smokes`, `/etc/oxide-arch-is-aarch64` (arm), opt-in
  `/etc/oxide-dhcpcd-enable`, `/etc/oxide-udhcpc-enable`.
- keymaps: `/etc/keymap` (us) + `/usr/share/keymaps/{us,uk,de,fr,es}.kmap`.
- terminfo: `/usr/share/terminfo/{d,l,s,v,x}/…` (dumb,linux,screen,vt100,xterm,xterm-256color).

---

## 8. Recent context (state.md + CHANGELOG)

- **D-roadmap status:** D1 util-linux, D2 shadow, D3 procps-ng, D4 iproute2, D5 iputils — **all merged** (#1343-#1347). On `main`, clean.
- **Next: D6 = systemd-musl as PID 1** (Chimera-style musl patches), then **D7 = drop busybox entirely.**
  Will surface kernel work: cgroups v2, real namespaces (mount/net/pid/ipc/uts/user),
  seccomp, capability propagation, dbus over AF_UNIX.
- **CHANGELOG.md is stale past ~Session 47 (#727)**; recent D-phases are NOT logged there.
  state.md + git log are the record.
- Open follow-ups: iputils ping ICMP unexercised; iproute2 `ip link` netlink EOF; util-linux
  mount non-PIE (busybox mount stays).

---

## 9. Stubs / placeholders / smoke-only shortcuts a production distro must replace

1. **PID 1 = busybox init** (+ rcS shell script). A production distro replaces this with
   systemd (the explicit D6 goal) or at minimum a real service manager + unit files.
2. **busybox is still the base-utility floor and the ONLY provider** of: init, halt/reboot,
   mount/umount, ifconfig/route, udhcpc, mdev, fdisk, swapon, nc, wget, dmesg. D7 = remove it.
3. **Static-everything, no real shared libs.** No system `/lib`/`/usr/lib` of `.so` files;
   ld-musl only loads test binaries. Production needs a real dynamic libc + shared lib tree.
4. **util-linux mount/umount are inert** (staged as `*.util-linux`, non-PIE won't load) —
   busybox mount is the real one. Needs PIE rebuild.
5. **Networking is hardcoded to QEMU slirp** in rcS (eth0 10.0.2.15, gw 10.0.2.2). No real
   network config management; no networkd/resolved; no `/etc/resolv.conf` until DHCP runs.
6. **dhcpcd (the real DHCP client) is disabled** (crashes); busybox udhcpc is the stand-in.
7. **iputils ping ICMP path unverified;** iproute2 `ip link` netlink dump broken.
8. **PAM is minimal:** only pam_unix + permit/deny/stub modules, dlopened by a *statically
   linked* libpam in sshd. No pam stack for login/su/passwd beyond what util-linux/shadow
   carry; modules are toy `.c` in `userspace/pam_modules/`.
9. **No syslog/journald, no cron, no dbus, no NTP, no logind.** journald/networkd/resolved
   are explicitly future D6 sub-PRs.
10. **shadow alice hash is a v1 sha512crypt placeholder**, to be regenerated at Drepper-2007
    parity (P14-08). root has an empty password.
11. **`/etc/oxide-*` marker files + the `oxide-smokes` harness** are test scaffolding shipped
    in the rootfs; a production image strips them (`OXIDE_INIT_SMOKES=0`).
12. **Vendored-but-unstaged:** `nano`, `gzip` (busybox gzip used instead), `dropbear`
    (superseded by openssh). Dead/legacy vendor weight.
13. **ssh host keys: ed25519 only** (openssh built without OpenSSL) — no RSA/ECDSA.
14. **32 MiB ext4 rootfs, no journal** (`-O ^has_journal`) — sized for the smoke set, not a
    real install; built non-deterministically (ext4 timestamps) each kernel build.
15. **Single hardcoded user `alice`** + nobody; no real account provisioning at first boot.
