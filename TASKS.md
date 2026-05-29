# Open tasks & deferred work

Single source of truth for things that need revisiting. Update on
every PR that opens, closes, or pivots an item. Tag closed items
with their merging PR and date.

## Distro Roadmap — drop busybox, become a real Linux server distro

Direction set 2026-05-28: stay on musl (server-class — no GNOME/
Wayland), drop busybox in favor of real distro programs, target
systemd-musl (Chimera-Linux-style patches) as PID 1 / service
manager. Bash is `/bin/sh` since F258.

| Phase | Vendor | Purpose | Replaces (busybox) |
|---|---|---|---|
| **D1** | util-linux 2.40 | `login`, `agetty`, `mount`, `su`, `umount`, `losetup`, `swapon`, `dmesg`, `kill`, `more`, `cal`, `script`, `mesg`, `tty`, `chsh`, `hexdump`, etc. | login, getty, mount, umount, su, dmesg, kill, more, tty, hexdump |
| **D2** | shadow-utils 4.16 | `useradd`, `userdel`, `usermod`, `groupadd`, `passwd`, `chage`, `gpasswd` | passwd, adduser (busybox lies) |
| **D3** | procps-ng 4.0 | `ps`, `top`, `free`, `vmstat`, `uptime`, `pgrep`, `pkill`, `pmap`, `tload`, `slabtop` | ps, top, free, vmstat, uptime |
| **D4** | iproute2 6.x | `ip`, `ss`, `tc`, `bridge`, `rtmon` | ifconfig, route (deprecated anyway) |
| **D5** | iputils | `ping`, `tracepath`, `arping` | ping, traceroute |
| **D6** | systemd-musl | PID 1, service mgr, journald, networkd, resolved | busybox init, our rcS script |
| **D7** | dropbusy | Final cut: remove busybox vendor; /sbin/init = systemd | -- |

Each phase = its own PR + boot smoke on both arches. Phases are
sequential — D2 builds on D1 etc. systemd-musl (D6) likely needs
several mini-PRs on its own (build, PID-1 swap, unit files,
journald, networkd, resolved).

Kernel surface that will surface: cgroups v2 hierarchies, BPF
LSM hooks, real namespaces (mount, net, pid, ipc, uts, user),
seccomp, capability propagation through exec, more inotify/
fsnotify edges, dbus over AF_UNIX. Each gap fixed in the same PR
that surfaces it per CLAUDE.md.

### T14 — Real `pam_unix.so` activation (medium impact)
F242 wired CLONE_SETTLS into `child.arch_ctx.fs_base`. F243
made `oxide_context_switch` `wrmsr` FS_BASE on the next task so
first-run pthreads start with correct TLS. `pthread_join` now
works end-to-end (`/bin/pthread_socketpair_probe` PASSes).

F244 narrowed to monitor↔preauth AF_UNIX socketpair message
loss between type 104 (request) and type 105 (response).

F245 ruled out basic AF_UNIX cross-process patterns —
/bin/socketpair_fork_probe round-trips length-prefixed messages
and works (including nonblocking + poll-with-infinite-timeout,
which exactly matches openssh's atomicio6 pattern).

F246 narrowed further: openssh's `UNSUPPORTED_POSIX_THREADS_HACK`
default means `pthread_create` is actually `fork()`. So the
sshpam_init_ctx path is a NESTED fork (monitor forks the
fake-pthread child while preauth is waiting on type 105 reply).
Pam_permit works because its `.so` is `-nostdlib` (no
DT_NEEDED) — pam_unix.so has DT_NEEDED libc.so, triggering
nested dlopen during PAM init. The difference between
working/hanging seems to be the nested dlopen side-effects
during fork, not the AF_UNIX path itself.

Next: build a minimal pam_unix variant with `-nostdlib` (just
the symbol exports + a hard-coded fail/success) — if that
works, the libc-load is the trigger. Then audit our
fork/dlopen interaction (likely an mmap or ld-musl reentry
issue under fork).

### T15 — ARM dynamic bash as `/bin/sh` boot wedge (low impact)
Staging dynamic bash at `/bin/sh` on ARM wedges init silently
post-keymap. Bash dynamically loads fine when invoked as
`/bin/bash` explicitly. Likely an ARM-specific kernel-side
edge in our dynamic-exec path during init. Workaround: keep
busybox-ash as `/bin/sh` on ARM.

## Recently closed

- **D5 iputils 20240117** — closed by **#1347 F263**. ping, tracepath,
  clockdiff, arping; static-musl both arches (meson/ninja). busybox
  `ping` applet dropped; iputils owns /bin/ping. Follow-ups below.
- **D4 iproute2 6.10.0** — closed by **#1346 F262**. ip/ss/tc/bridge/
  rtmon/lnstat/nstat/ifstat, static-musl both arches.

- **T17 Vim cross-build + runtime smoke** — closed by **#1330 F250 (ncurses)** + **#1331 F251 (vim cross-build)** + **#1332 F252 (terminfo db)** + **#1334 F254 (less, also ncurses)** + **#1336 F256 (vim_smoke wired)**. Vim ex-mode :qa! exits 0 on both x86 and ARM.
- **T16 Growable kernel heap (vmalloc-equivalent)** — closed by **#1328 F247** (per-instance KAlloc grow hook → PMM buddy via HHDM; STATIC_HEAP back to 64 MiB; hosted test covers grow path).
- **T13 SSH-connect smoke through PAM dlopen** — closed by **#1314 F231** (real PAM dlopen via dynamic sshd + pam_permit.so).
- **T12 wait4 status decode `$?=255`** — closed by **#1320 F237** (clear SIGCHLD pending bit when wait4 drains last zombie).
- **T10 multi-conn ssh smoke** — closed earlier (boot-smoke-ssh.sh tail-tools + pty).

## Open follow-ups (non-blocking)

- **iputils ping runtime ICMP path** — D5 staged + boots, but ping
  send/recv (raw/dgram ICMP socket) not yet exercised in smoke.
  Verify `ping -c1 127.0.0.1` on both arches; fix any kernel ICMP
  socket gap in the same follow-up.
- **rootfs `pthread_socketpair_probe` not reproduced** — `xtask
  rootfs` pthread build step emits no binary and no failure (staging
  WARNs missing); manual `musl-gcc -static -pthread` builds it fine.
  Pre-existing; image is reproducible without it (T14 diagnostic, not
  boot/CI-relevant). Root-cause the silent skip in xtask main.rs.

## Notes for the next session

- The kernel-side investigation paths are tracked in `state.md`
  (which is short-lived). The DURABLE work queue lives here.
- When opening a new branch, add an entry here; when closing,
  move it to the "Recently closed" section with the merging PR.
- If a task has a multi-step plan, add a `Plan` sub-list under it.
