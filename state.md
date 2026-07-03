# state.md — session handoff

## Headline
**GNOME bring-up: the EXIT_NAMESPACE(226) cascade AND the D-Bus outage are fixed** — three fixes merged to `origin/main` (PR #2311, #2312, #2313). Boot progressed from total-failure to reaching basic/sysinit/sockets/timers/getty/local-fs targets with the system bus up. **Current blocker: `PrivateUsers=yes` services (upower, …) fail EXIT_USER(217) in systemd's `setup_private_users`, and upower's `Restart=on-failure` retry loop delays multi-user.target → graphical.target → gdm never starts.**

## Merged this session (all boot-verified, both arches smoke to login)
- **#2311** `mount_setattr AT_EMPTY_PATH + mount-aware bind target` — killed the deterministic domainname `-EBUSY` (systemd `bind_remount_recursive` 32-retry cap). 6 mount-subsystem root causes.
- **#2312** `O_PATH must not invoke the device driver open` (Linux FMODE_PATH) — killed the residual concurrency 226 (ProtectKernelLogs' inaccessible devt-0 char over /dev/kmsg, O_PATH-chased → `lookup_chrdev` ENXIO). 226 → 0/3 boots.
- **#2313** `socketpair(AF_UNIX) must report SO_DOMAIN=AF_UNIX` — dbus-broker rejected its controller fd (getsockopt SO_DOMAIN was AF_INET) → system bus down → every dbus service timed out. Now dbus-broker starts.

## Current blocker — EXIT_USER(217), TWO distinct causes (next session starts here)
Many services exit `217/USER` (upower ~41×/boot via Restart loop). The kernel `[EXIT]` recent-syscall ring shows TWO different failing paths:

**Cause A — `setup_private_users` (PrivateUsers=yes; upower, exec-invoke.c:4982).** Ring: fork `(sd-userns)`, `unshare(CLONE_NEWUSER)`. ALL its direct syscalls VERIFIED to SUCCEED: unshare rv=0; child opens `/proc/<ppid>/uid_map`,`gid_map` rv=3; child writes maps `"65534 65534 1\n"` rv=14. So NOT a failing syscall.
- **DISPROVEN this session:** I hypothesized the throwaway per-open `/proc/<pid>/{uid_map,gid_map,setgroups}` inodes (readback returns default) and implemented persistent per-(tid,field) storage — it did NOT reduce 217 (still 50). Reverted. So it is not a uid_map readback.
- **Not yet checked:** the `(sd-userns)` child's EXIT STATUS (parent `wait_for_terminate_and_check`); eventfd sync between parent/child; whether the parent's post-unshare state (caps/uid in the new userns — our `unshare(CLONE_NEWUSER)` in `272_unshare.rs` only allocates a ns id, does not remap uid/caps) makes a later step fail.

**Cause B — NSS/userdb varlink lookup (get_fixed_user for `User=` services, exec-invoke.c:4503).** Ring: `socket(AF_UNIX)`→3, `connect`→0, setsockopt/getsockopt, `sendmsg`→366 (all succeed), then close+exit 217. The request is SENT but the RESPONSE fails/empty → getpwnam returns error. This is nss-systemd talking to the userdb varlink socket (`/run/systemd/userdb/io.systemd.Multiplexer`); systemd-userdbd is socket-activated but may not be answering (check if userdbd itself starts). `nsswitch.conf`: `passwd: files systemd`, `group: files [SUCCESS=merge] systemd` — nss-systemd is consulted for every lookup.

**Approach that FAILED to get the exact error:** systemd executor errors go to the journal via a mechanism not capturable through write(fd2)/writev(fd2)/sendmsg(journal) — all returned nothing useful. Use the `[EXIT]` ring + exec-invoke.c cross-ref. To advance: (a) trace recvmsg/read on the userdb socket to see the response for Cause B; (b) trace the `(sd-userns)` child exit for Cause A; or (c) find a way to surface the executor's `log_exec_error_errno` text (maybe it uses a sealed memfd + SCM_RIGHTS to journald).

## Also seen (lower priority, may clear once userns fixed)
- `accounts-daemon`: `Failed at step STATE_DIRECTORY ... Bad file descriptor` (intermittent) — EBADF in state-dir setup.
- `/sys/fs/cgroup/system.slice/<svc>/{cpu.stat,memory.peak,memory.swap.peak,cgroup.events,memory.zswap.writeback}` ENOENT — missing cgroup accounting files (systemd tolerates, but worth adding).
- os-release read EBADF, utmp write EIO (pre-existing, noted earlier).

## Boot/diagnosis notes
- **Diagnostic cmdline**: `../oxide-images/imagectl/src/main.rs` line ~963 GRUB menuentry (NOT git-tracked). Default `quiet` (restored). For systemd errors on serial: `systemd.log_target=kmsg systemd.journald.forward_to_console=1` (now reliable after #2312). NOTE: the systemd EXECUTOR's detailed "Failed at step X" errors do NOT reach kmsg/stderr/journal-sendmsg in a capturable way — I tried write(fd2)/writev(fd2)/sendmsg(journal) and all failed; use the kernel `[EXIT]` recent-syscall ring + `exec-invoke.c` cross-reference instead.
- Boot loop: `cd ../oxide-images && make kernel ARCH=x86_64 && make boot PROFILE=live-gnome ARCH=x86_64 && bash oneboot.sh output/x.log <secs>`. Real boot >2000 lines; ~1400/8 = GRUB-partial, re-run.
- Kernel `[EXIT]` watchdog: `exe=` + `code=`(the raw `exit_group` arg; 217=EXIT_USER,226=EXIT_NAMESPACE,219=EXIT_GROUP) + recent-syscall ring (newest first). x86 nr map: 257=openat, 46=sendmsg, 272=unshare, 20=writev, 1=write.
- systemd 257 sources: `gh api repos/systemd/systemd/contents/src/core/exec-invoke.c?ref=v257 --jq .content | base64 -d`. dbus-broker: `repos/bus1/dbus-broker`.
- Bash sandbox can't kill qemu; `pkill -9 -f qemu-system-aarch64` with `dangerouslyDisableSandbox: true`. Stale qemu blocks next boot.
- Ledger `metadata/index.md`: B next = 300 (unused branch B300 was deleted). Use B300 for the userns fix.

## First task next session
`git checkout main && git pull`. Implement persistent per-task `/proc/<pid>/{uid_map,gid_map,setgroups}` (see analysis above), boot live-gnome, verify upower `217/USER`→0 and multi-user/gdm progress. Keep going down the graphical-target dependency chain until GNOME runs (active `/goal`).
