# 28 TTY + PTY

FROZEN 2026-05-02. Dep:`01`,`02`,`06`,`16`,`19`,`24`. Provides:`getty`/`login`/shells, `openssh`.
## 1 Purpose

Terminal subsystem: line discipline (N_TTY canonical mode, raw mode), session/process-group control, signal generation (Ctrl-C, Ctrl-Z), UNIX98 PTY pairs.

## 2 Invariants (frozen)

1. PTY pair: master + slave `Inode`s share a buffer pair; close of one wakes the other.
2. Session/pgrp: each tty has one foreground pgrp; signals (`SIGINT`,`SIGTSTP`,`SIGQUIT`,`SIGHUP`) target it.
3. Canonical mode line buffer ≤ `MAX_CANON=4096`; bytes beyond drop with bell.
4. Ctrl-C (`VINTR`) generates SIGINT to fg pgrp; same for `VQUIT`/SIGQUIT, `VSUSP`/SIGTSTP, `VEOF` end-of-input.
5. `setsid` + opening tty without `O_NOCTTY` → tty becomes controlling tty of the session (Linux semantics).

## 3 Public ifc

```rust
pub fn pty_alloc() -> KR<(Arc<File> /*master*/, Arc<File> /*slave*/, u32 /*idx*/)>;

pub trait Tty: Send+Sync {
    fn read(&self, buf:&mut [u8]) -> KR<usize>;
    fn write(&self, buf:&[u8]) -> KR<usize>;
    fn ioctl(&self, cmd:u32, arg:usize) -> KR<u64>;
    fn poll(&self) -> PollMask;
}
```

ioctls: `TIOCGWINSZ`, `TIOCSWINSZ`, `TIOCGPGRP`, `TIOCSPGRP`, `TIOCSCTTY`, `TIOCNOTTY`, `TCGETS`, `TCSETS`, `TCSETSW`, `TCSETSF`, `TIOCGSID`, `TIOCSPTLCK`, `TIOCGPTN`.

## 4 Line discipline

N_TTY (canonical+raw). State per-tty:
- `termios`: c_iflag, c_oflag, c_cflag, c_lflag, c_cc[NCCS].
- canonical line buffer, "echoed but not yet read" buffer.
- input/output queues.

Edits in canonical mode: erase (`VERASE`), kill (`VKILL`), word-erase (`VWERASE`), reprint (`VREPRINT`). Echo via `c_lflag & ECHO`.

Output processing: `OPOST`/`ONLCR`/`OCRNL`.

## 5 PTY mux

`/dev/ptmx` open allocates new pair; slave appears at `/dev/pts/<n>` (devpts FS).

devpts is a `Filesystem` (per `16`); mounted at `/dev/pts` automatically.

## 6 Session/pgrp

Per task: `session_id`, `pgrp_id`. `setsid()` creates new session; `setpgid()` moves task to pgrp. tty has `tty.session`,`tty.fg_pgrp`.

Background process attempts read on tty: SIGTTIN (or EIO if blocked).
Background process attempts write with `TOSTOP`: SIGTTOU.

Hangup: `vhangup`/loss-of-carrier → SIGHUP to session leader and fg pgrp; tty becomes ghost (operations return EIO).

## 7 Concurrency

- Per-tty spinlock class `Tty`.
- Wait queues: read, write, exception.
- Buffer is bounded MPMC; readers drain canonical-line at a time.

## 8 Perf budget

| Op | p99 cy |
|---|---|
| Single-byte write to PTY (raw mode) | ≤ 4000 |
| `read` of 1 line (40 chars) canonical | ≤ 6000 |
| `ioctl(TCGETS)` | ≤ 800 |

## 9 Test contract (frozen)

- Open `/dev/ptmx`, grant via `unlockpt`+`grantpt`-equivalent, open slave; bidirectional echo; close master closes slave.
- Canonical mode: send "hello\b\b\b\bworld\n"; reader sees `held world\n` after edits.
- Ctrl-C: write 0x03 to PTY master; SIGINT delivered to slave's pgrp.
- Background read: bg pgrp reads → SIGTTIN; resumes with SIGCONT.
- `bash` interactive in QEMU+busybox image: history, line-editing, signals all work.
- openssh-server (when integrated v1): `ssh user@host` returns interactive shell.
- Coverage ≥85%.

## 10 Failure modes

- PTY slave open after master close: ENOENT (devpts removed the node).
- Session leader exits with controlling tty: SIGHUP to all in session, then tty becomes ghost.

## 11 Debug

`debug-tty`: per-byte trace of input/output; termios state dump.

## 12 Cross-spec

`16` (devpts as FS), `19` (`/dev/pts`,`/dev/ptmx`), `24` (signal delivery), `13` (pgrp for signal targeting).

