# state.md — session handoff

## Headline
**GNOME bring-up: FOUR structural blockers fixed & merged this session.** The EXIT_NAMESPACE(226) cascade, the dead system D-Bus, and the EXIT_USER(217) cascade are all gone. Boot now reaches basic/sysinit/sockets/timers/getty/local-fs targets and services actually RUN. **Current blocker: systemd's D-Bus connection is "terminated" when it installs the `NameOwnerChanged` match**, so Type=dbus services (upower/udisks2/polkit/…) are never detected ready → they time out (~90s each) → multi-user.target / graphical.target never reached, gdm never starts.**

## Merged this session (all boot-verified, both arches smoke to login)
- **#2311** `mount_setattr AT_EMPTY_PATH + mount-aware bind` — killed the deterministic domainname 226 (6 mount root causes).
- **#2312** `O_PATH must not invoke the device driver open` (FMODE_PATH) — killed the concurrency 226 (/dev/kmsg inaccessible-char ENXIO).
- **#2313** `socketpair(AF_UNIX) SO_DOMAIN=AF_UNIX` — brought up the system D-Bus (dbus-broker rejected its controller fd).
- **#2314** `eventfd blocking read must BLOCK not EINVAL` — killed EXIT_USER(217) for PrivateUsers= units (the `(sd-userns)` eventfd barrier got EINVAL). Verified 217→0, park→wake 4–20ms, no smoke regression.

## Current blocker — analysis (next session starts here)
Symptom: `Unexpected error response on installing NameOwnerChanged signal match: Connection terminated` — logged 75×/boot. systemd (PID1) connects to the system bus and calls `AddMatch` for `NameOwnerChanged` (org.freedesktop.DBus) to learn when a Type=dbus service acquires its `BusName=`. The response is "Connection terminated" — **the socket to dbus-broker drops on that request.** Consequence: systemd never sees a service acquire its name → every Type=dbus unit (upower `org.freedesktop.UPower`, udisks2, switcheroo, polkit, NetworkManager…) is reported `Failed with result 'timeout'` after its ~90s start timeout, and its Restart= loop re-runs it. multi-user.target waits on those jobs → graphical.target queued, never reached. (upower now gets PAST user setup — it exits 265/271 on the SIGTERM systemd sends at the timeout, not a real crash.)
**To investigate:** why does the systemd↔dbus-broker AF_UNIX connection terminate on the `NameOwnerChanged` AddMatch specifically? Candidates: (a) dbus-broker closes the connection handling that message (a message it dislikes → look at dbus-broker's driver AddMatch path, or a message-size / fd-passing / SO_PASSCRED issue on our AF_UNIX socket); (b) our AF_UNIX socketpair/stream sendmsg/recvmsg mishandles a specific message (large match rule, ancillary data, or a control message). Method: capture the exact bytes/ancillary systemd sends before the drop, and whether dbus-broker or the kernel closes the fd (trace close/shutdown on the bus socket, and dbus-broker's stderr via the `[EW ...]`/kmsg path). Cross-ref dbus-broker source `repos/bus1/dbus-broker` (driver/`org.freedesktop.DBus` AddMatch + connection teardown) and systemd `sd-bus` `bus_add_match`.

## Boot/diagnosis notes
- **Diagnostic cmdline**: `../oxide-images/imagectl/src/main.rs` ~line 963 GRUB menuentry (NOT git-tracked). Default `quiet` (RESTORE when done). systemd errors on serial: `systemd.log_target=kmsg systemd.journald.forward_to_console=1` (reliable now).
- **Executor error capture that WORKS**: the systemd executor's step failures do NOT reach write(fd2)/writev(fd2)/sendmsg(journal). BUT a `safe_fork` helper (setup_private_users' `(sd-userns)`, can_mount_proc's `(sd-proc-check)`) reports its errno as a **4-byte write to an errno pipe** — trace `write` where `cnt==4` and the i32 is in `-1..-255` to get the exact failing errno, then `sched::diag::dump_recent_for(tid)` (make it `pub`) to get that child's ring. This is how #2314 was found.
- Kernel `[EXIT]` watchdog: `exe=` + `code=`(raw exit_group arg) + recent-syscall ring. x86 nr: 0=read,1=write,2=open,46=sendmsg,47=recvmsg,110=getppid,247=waitid,257=openat,290=eventfd2,293=pipe2.
- Real boot >2000 lines; ~1200/8 = GRUB-partial, re-run. Bash sandbox can't kill qemu → `pkill -9 -f qemu-system-aarch64` with `dangerouslyDisableSandbox: true`; stale qemu blocks the next boot. `make smoke-arm` runs 3 attempts (up to 3×timeout) — a bash timeout may cut it off mid-run though attempt 1 already PASSED.
- Ledger `metadata/index.md`: B next = 301.

## First task next session
`git checkout main && git pull`. Investigate the systemd↔dbus-broker "Connection terminated on NameOwnerChanged AddMatch" (see analysis). Fixing it should let Type=dbus services signal ready promptly → multi-user.target → graphical.target → gdm. Keep going down the dependency chain until GNOME runs (active `/goal`).
