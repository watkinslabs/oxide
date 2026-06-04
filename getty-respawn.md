# getty-respawn — analysis

Goal: after a console logout, systemd restarts `console-getty.service`
and a fresh `oxide login:` prompt appears. Today it does not.

## Systems involved

1. **Login chain (the session).** `console-getty.service` runs
   `/sbin/getty` = **util-linux agetty** (`vendor/util-linux/.../agetty.c`).
   agetty → `login` (PAM) → user shell. agetty/login are a fork chain
   (separate pids), all in one **session** created by `setsid`.

2. **systemd PID1 event loop.** `sd-event` blocks in
   `epoll_wait(timeout=-1)` on: a **SIGCHLD signalfd** (child reaping)
   and **timerfds** (`RestartSec`). On a service exit it reaps via
   `waitid`, marks the unit, and (Restart=always) schedules a restart.

3. **Kernel: exit/reap/signal.** `sys_exit` → `signal_child_exit`
   posts SIGCHLD to the parent + wakes it. `wait4`/`waitid` reap.

4. **Kernel: TTY/VT/session.** `/dev/console` = VT-0 foreground alias
   (`kernel/src/dev/console.rs`). Per-VT `VT_SID` (controlling session)
   + `VT_FG_PGID` (`crates/kernel/tty/src/live.rs`). Set by
   `TIOCSCTTY`/`TIOCSPGRP`. Writes → `klog::write_raw` → serial (+fbcon
   aux sink). Reads ← VT RX ring (interrupt-driven UART RX, F373).

5. **Kernel: fd table + exec.** `FdTable` (`vfs/src/fdtable.rs`):
   `Vec<Option<Arc<File>>>` + per-fd `cloexec`. `execve` calls
   `close_on_exec()` (drops CLOEXEC slots to `None`, keeps Vec len).

## What works now (merged this session)

- `wake_task_for_signal` (#1518): SIGCHLD post wakes a parent parked in
  epoll_wait, not just wait4 parkers.
- epoll_wait 20ms safety re-scan deadline (#1518): an idle epoll wakes
  for level-ready timerfd/signalfd (RestartSec fires).
- Result: systemd **does** reap the dead getty and restart the service
  (`Scheduled restart job` → `Started Console Getty`). Confirmed in the
  serial log.

## The failure (observed)

The respawned agetty exits with wait-status low byte **9**, writing
**nothing** to the console (no banner, no `oxide login:`). systemd
restarts it twice (counter → 2) then gives up. Serial also shows:
- `Failed to lock /dev/console … Resource temporarily unavailable`
  (systemd's `acquire_terminal` flock; "proceeding without lock").
- `Failed to reset TTY ownership/access mode of /dev/console to 0:5 …
  Invalid argument` (chown of the console inode; "ignoring").

agetty syscalls seen (PARTIAL — ad-hoc filtered traces, unreliable):
`TIOCGWINSZ` on fd 3 then fd **33** repeatedly. The high fd suggests
agetty's tty fd isn't landing where it expects.

## agetty's controlling-tty discipline (agetty.c open_tty)

```
fd = open("/dev/console", ...)          # first open
fstat/isatty sanity
if (tcgetsid(fd) < 0 || pid != tcgetsid(fd)) ioctl(fd, TIOCSCTTY, 1)
close(STDIN_FILENO); close(fd); close(STDOUT); close(STDERR)   # F_HANGUP
vhangup()                               # SIGHUP whole session
open(buf, O_RDWR|O_NOCTTY|O_NONBLOCK)    # MUST return fd 0:
   if (... != 0) log_err("cannot open as standard input")   # FATAL
ioctl(STDIN_FILENO, TIOCSCTTY, 1)
... later: ioctl(STDIN_FILENO, TIOCGWINSZ) → if 0, default 24x80
```

Two hard requirements agetty places on the kernel:
- **the post-vhangup re-open must return fd 0** (it just closed 0/1/2/fd,
  so fd 0 is the lowest free — relies on `open` returning lowest-free).
- **`vhangup()`** must not kill agetty itself before it re-opens.

## Hypotheses (ranked, to verify with a CLEAN per-syscall trace)

H1. **vhangup kills the respawned agetty.** `sys_vhangup` SIGHUPs every
    task whose `sid == caller.sid`. After agetty `setsid`s, its session
    = itself, so vhangup SIGHUPs *itself*. SIGHUP default = terminate.
    On first boot it survived (?) — need to confirm what differs. Status
    low-byte 9 ≠ SIGHUP(1) though, unless status is exit(9) not a signal.
    → wait-status 0x109: `exit_status = args.a0` (the exit() arg), so
    agetty called `exit(9)`-ish (265 & 0xff). agetty `log_err` →
    `exit(EXIT_FAILURE=1)`; 9 doesn't match cleanly → re-check the value.

H2. **post-vhangup re-open doesn't return fd 0** → agetty `log_err`
    ("cannot open as standard input") → fatal. The fd-33 evidence. Cause
    candidates: `close()` not freeing the slot; `open` not returning
    lowest-free; leaked non-CLOEXEC fds shifting numbering.

H3. **VT controlling-session staleness** — RULED OUT for the prompt:
    added `release_session` on session-leader exit; no change.

## Next step (the clean diagnostic, replacing ad-hoc traces)

Add ONE gated full-syscall tracer for a single pid range at the syscall
dispatch: log `(nr, a0, a1, a2, ret)` for the respawned agetty only.
Read the EXACT sequence from `setsid` to `exit` — which syscall returns
the error agetty turns fatal — then fix that one kernel behavior. No
more guessing from filtered partial traces.
