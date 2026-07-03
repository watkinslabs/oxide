# state.md — session handoff

## Headline
**GNOME reaches graphical.target + gdm; greeter still not rendered.** Major win
this session: udev was completely non-functional (processed ZERO devices); root
cause found + fixed — **netlink uevents carried no SCM_CREDENTIALS**, so modern
`sd-device-monitor` dropped every uevent. udev now works: `/run/udev/data/c226:0`
written with `G:master-of-seat`. Next wedged daemon: **systemd-logind** (not
creating `/run/systemd/seats/`, doesn't answer its bus). Chain: udev ✅ →
logind ❌ → seat0 CanGraphical → gdm greeter.

## Merged this session (4 PRs, #2324–#2327, all boot-verified)
- #2324 netlink recvfrom must honour MSG_PEEK/MSG_TRUNC — udevd size-probe no
  longer destroys the uevent.
- #2325 `/proc/<pid>/fd/<n>` magic-symlink must re-open fresh with caller flags
  (not dup the fd) — killed os-release / StateDirectory EBADF (systemd chase()+
  fd_reopen of an O_PATH fd).
- #2326 pidfd poll must report EPOLLIN only after target exits — killed
  dbus-broker-launch's ~3900×/boot waitid busy-spin (sd-event child source on an
  always-readable pidfd).
- **#2327 netlink uevent monitor: SCM_CREDENTIALS + enqueue-wakes-pollers +
  correct source nl_groups — THE udev-wall fix.** udevd read every uevent but
  dropped all (no SO_PASSCRED cred record). Now processes card0 → 71-seat.rules
  → master-of-seat tag.

## Merged since (5th PR)
- #2328 `/proc/<pid>/fd` must list the TARGET pid's fds, not the caller's
  (`ProcSelfFdOps` used `current()`). Real Linux-contract bug AND it had been
  misleading kernel debugging (daemon fd inspection showed the debugger's fds).

## Current blocker (next lane): systemd-logind wedged
Confirmed via debugfs-injected diagnostic unit (dumps to /dev/ttyS0 at
graphical.target):
- `/run/systemd/seats/` is EMPTY — logind creates NO seat (not even default seat0).
- `loginctl seat-status seat0` → "Connection timed out" — logind's bus/IPC
  unresponsive (same shape as udevd-was: daemon up, State S sleeping, not
  servicing its sockets).
- gdm is active but launches no greeter session (seat0 never CanGraphical).
Investigate logind like udevd: does its udev monitor (group 2, cooked) receive
the card0 event? does its sd-bus/varlink event loop wake? Likely another
netlink/af_unix/creds-class kernel bug OR a logind-specific one. The SCM_CREDS
fix already applies to logind's cooked monitor reads (recvmsg, all proto-15).

### logind facts gathered (now that /proc/pid/fd works, #2328)
- D-Bus method calls WORK: `busctl call systemd1 ... GetUnitFileState gdm.service`
  → `"enabled"` rc=0. So dbus-broker + AF_UNIX method-call replies are fine.
- `busctl list`: `org.freedesktop.login1` is `(activatable)` with EMPTY
  connection — the running logind (pid ~69) never acquired its well-known name.
  → `busctl call login1 ...` and `loginctl` time out; gdm can't query seats.
- logind DOES have its sockets (fd 5 = `socket:[…]`) — it's connected, not
  missing fds. And it holds **~87 `/run/systemd/inhibit/N.ref` inhibitor fds +
  paired `anon_inode:[pidfd]`** — abnormally many (normal ≈ 2-5). STRONGEST
  unchased lead: is something looping on `Inhibit()`, or is logind failing to
  release inhibitors when holders die (pidfd-signal / epoll-wake)? The pidfd
  poll fix (#2326) should make holder-exit wake logind — verify it does for
  logind's inhibitor pidfds specifically.
- logind seen frozen in `epoll_wait` (nsyscalls flat 5352 over 50→58s) in an
  EARLIER boot, but later had 87 inhibitors → it IS processing some D-Bus. The
  contradiction (processes Inhibit but doesn't own login1 / answer ListSeats)
  is the crux to resolve NEXT.
- `/run/systemd/seats/` empty, `/run/udev/tags/master-of-seat/` absent in some
  boots → logind never attaches card0 → seat0 not CanGraphical → no greeter.

### NOTE: concurrent driver lane active in the shared tree
Uncommitted driver changes (virtio-blk/rng/snd, drv/model.rs, pci-boot,
mm-pmm/setup.rs, sound, block/registry.rs, devfs/misc.rs, driver_anal.md)
appeared in the working tree mid-session — another lane (codex/driver-fixes?).
LEFT UNTOUCHED. Do NOT commit/clobber them; coordinate before boot-verifying on
the shared tree (its artifacts may include this WIP).

## Diagnosis harness (USE THIS — it ended the thrashing)
- **Inject a diagnostic oneshot into the rootfs via debugfs (unprivileged, no
  mount):** write `/usr/local/bin/oxdiag.sh` (`exec >/dev/ttyS0`), a
  `graphical.target.wants/oxdiag.service` symlink; `debugfs -w -R "write ..."`
  + `sif ... mode 0100755` + `symlink ...` on
  `../oxide-images/output/live-gnome-x86_64-root.img`. Reads real runtime state
  (loginctl, ls /run/udev/data, cat /run/systemd/seats/seat0, /proc/<pid>/status).
- **sysrq over serial:** boot with `-serial stdio`, feed stdin
  `( sleep N; printf '\000t' )` → `[sysrq] task dump` shows every task's
  state + last_syscall + nsyscalls + exe (pins a wedged daemon's blocking
  syscall). `\000w`=watchdog, `\000c`=cpus, `\000b`=backtrace.
- Boot script: `/tmp/claude-.../scratchpad/boot.sh <log> <secs>` (single qemu,
  `-serial file:`); `boot_sysrq.sh` for the stdin-driven sysrq variant.
- **GOTCHA:** `/proc/<pid>/fd` lists the CALLER's fds, not the target pid's
  (`ProcSelfFdOps::iterate` uses `current()`) — do NOT trust it. Separate bug.

## Boot / build
- `cd ../oxide-images && make kernel ARCH=x86_64` then
  `cd ../kernel && cargo run -q -p xtask -- artifacts --arch x86_64` then
  `cd ../oxide-images && cargo run -q -p imagectl -- build-boot --profile
  live-gnome --arch x86_64`. (`make boot` wrapper exits 1 spuriously — use
  imagectl build-boot directly.) Then boot.sh. ~half of cold boots GRUB-hang
  (<1000 lines) — re-run. Diagnostic cmdline in imagectl/src/main.rs (~L963,
  NOT git-tracked): currently kmsg+forward_to_console; restore `quiet` before done.
- Ledger `metadata/index.md`: B next = 311.
