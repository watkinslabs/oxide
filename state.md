# Session hand-off — 2026-05-30

## TL;DR
Branch `B18-login-smoke-fix`. Three commits done; one more to add (the
TIOCSCTTY VT fix). PAM auth works end-to-end on console + SSH. Shell
hand-off works for our own `/bin/login_sim` reproducer. util-linux
`/sbin/login` itself still fails between `pam_setcred(REINIT)` and
`fork_session` — root cause not yet isolated. **Do not claim "login
works" until you see `$` and `uid=1000(alice)` after typing `id` on
the console serial line.**

## Commits on this branch
- e5217cc1 — upstream Linux-PAM 1.7.2; deleted `userspace/pam_modules/`;
  fixed `/dev/console::read()` to drain the ring instead of returning
  Ok(1) (B18 input-mangling).
- 87351ad2 — `crates/kernel/mm-vmm/src/address_space.rs::fork_cow_pages`
  now COW-shares File-backed VMAs (was skipping them, child SIGSEGV'd
  on first libpam.so access).
- ad1dc5b4 — drop `-Dpam-debug=true` build flag (chore).

## To commit before opening PR
- `kernel/src/syscalls/ioctl.rs` TIOCSCTTY VT branch now sets
  `set_foreground_pgid(vt, cur.pgid)` to mirror the PTY branch.
  Without this, busybox `sh`'s job-control sees `tcgetpgrp(0)==0` ≠
  its own pgrp on the freshly-controlled VT and the shell stops
  itself before printing a prompt. Verified with login_sim.
- `userspace/login_sim/` — the reproducer. Builds dynamic against
  libpam.so.0, staged as `/bin/login_sim`. Runs PAM auth + acct +
  setcred(ESTABLISH/REINIT) + open_session, then initgroups +
  setgid + chown_tty + chmod + vhangup + TIOCNOTTY + fork →
  child:setsid+open_tty+TIOCSCTTY+setuid+chdir+execvp /bin/sh. With
  the TIOCSCTTY fix it gives a working `oxide:~$` prompt on the
  console. Useful as a permanent diagnostic.
- xtask change to build + stage login_sim.

## Open: util-linux login still respawns post-PAM
Real `/sbin/login` invoked by `agetty` from inittab still fails after
my TIOCSCTTY fix. Sequence:

1. agetty prompts `oxide login:`, user types `alice`
2. login execs, PAM auth + acct + setcred + open_session + setcred
   all return Success
3. login does init_environ (pam_getenvlist) — visible in serial
4. login then does `fork_session` (with `parent: close(0/1/2) + wait`,
   `child: setsid + open_tty(/dev/ttyS0) + TIOCSCTTY + …`)
5. After fork_session returns in child, login does setuid + chdir +
   pam_end + execvp `/bin/sh -sh`
6. Shell never prints a prompt; agetty respawns after login exits
   with status 1

login_sim replicates that EXACT sequence (verified syscall-by-syscall
including `process_title_init`/`update`, and the same parent-close +
wait scheme) and produces a working shell prompt. So the broken
piece is something specific to util-linux's login binary that
login_sim isn't reproducing.

Suspects to investigate next session:
- `log_lastlog` — opens /var/log/lastlog (file doesn't exist, should
  silently bail); but pwrite at offset `1000 * sizeof(ll) = 292000`
  bytes creates a sparse file. Our ext4 write path for sparse holes
  may not handle that — check `crates/kernel/ext4` for pwrite + hole
  behavior, or just `touch` /var/log/lastlog into the rootfs.
- `log_utmp` — opens /var/run/utmp (also missing, should silently
  bail).
- `display_login_messages → motd` — reads /etc/motd, silent if
  missing.
- The `closelog()` inside `fork_session` (before fork) — does
  anything if /dev/log is unbound.
- Login's actual exit code is 1 (EXIT_FAILURE), so something
  exit()s with EXIT_FAILURE between pam_getenvlist (visible) and
  fork_session (invisible). Likely candidates: `setgid` failure
  path (line 1510-1513) or `chdir(/)` after home chdir failed (line
  1542-1544). With current /home/alice mode 0755 root:root, alice
  should chdir fine. setgid(1000) from root should succeed.

Diagnostic plan: copy util-linux login.c locally, build with
`-DDEBUG` and ship as a debug-only `/bin/login_dbg`, observe the
exact exit point. (NOT a vendor patch — a debug build with extra
prints, kept out of the production build.)

## Other findings worth keeping
- vhangup currently broadcasts SIGHUP to **every** task in the
  caller's session, not just those whose controlling tty matches.
  When login (called from rcS without a setsid'd session leader) does
  vhangup, sshd reports `Received SIGHUP; restarting.` and re-binds
  port 22. Cosmetic in normal use (agetty does setsid first), but
  worth tightening: `kernel/src/syscalls/proc.rs::sys_vhangup`
  should scope SIGHUP to processes whose ctty matches the caller's,
  per Linux semantics.
- `/dev/log` no longer registered in devfs — userspace syslogd is
  expected to bind it as AF_UNIX. devtmpfs needs to actually permit
  the bind for syslogd to start; until then, libpam's pam_syslog
  messages disappear and rcS's `syslogd -O /var/log/messages` is
  a no-op.

## Run-down for next session
1. Commit the TIOCSCTTY VT fix + login_sim + xtask change as one
   commit (`fix(tty,xtask): TIOCSCTTY VT foreground_pgid + login_sim
   B18 reproducer`).
2. Investigate the remaining util-linux login post-PAM exit-1 with
   the debug-build approach above.
3. Add `touch`-style empty files for /var/log/lastlog + /var/run/utmp
   in xtask staging so login's silent-bail paths don't trip on
   anything in our ext4.
4. Open PR after console login lands.
