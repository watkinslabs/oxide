# state — hand-off

Branch: F202-ssh-exec-segfault (in flight → PR pending).
Workspace: spec-lint clean, x86 smoke 16s.

## Endgame this session: working SSH login

**`ssh ... 'echo HELLO; id'` now returns output over the SSH exec
channel.** Captured client side:

    HELLO
    uid=1000(alice) gid=1000 groups=1000,10(wheel),100(users)

Subsequent commands in the same exec request still stall — the
chain pauses after the first couple of outputs — but the
pipe→relay→ssh-socket path is unambiguously alive.

## What this PR lands

**sys_select consults inode.poll().**
`kernel/src/syscalls/select.rs` was hardcoded `(true, true)` for
every non-pty char dev and every non-char-dev file, so dropbear's
session pump (`select(read_pipe, sock)`) never reflected actual
queue state. Pipes, sockets, ptys, regular files all now project
through the inode-trait poll mask:

    got_read  = (mask & (POLL_IN  | POLL_HUP)) != 0
    got_write = (mask &  POLL_OUT)             != 0

POLL_HUP folded into read-ready so EOF wakes a peer's read loop
(Linux pipe(7) and socket select semantics).

## Verified

- spec-lint clean.
- x86 smoke 16s.
- `ssh -p 2222 alice@127.0.0.1 'echo HELLO; id'` returns
  HELLO + uid=1000(alice) over the SSH exec channel (was: hang +
  Aiee segfault pre-F202).

## Open — next bug

After the first one or two commands in a single exec request,
the channel stalls. Probably the pipe→ssh forward isn't draining
on POLL_HUP after the shell exits (we wake on HUP, read returns
bytes, but the EOF-on-empty path may not be plumbed back into
SSH2 CHANNEL_EOF / CHANNEL_CLOSE). Next session: confirm shell
exit_status reaches dropbear, then trace channel close emission.

## Out-of-scope (deferred for later PRs)

- TCP_INFO field completeness past tcpi_total_retrans (F188).
- SCM_RIGHTS over SOCK_STREAM (F189 covers SOCK_DGRAM only).
- AF_NETLINK ROUTE / sock_diag completeness (D45 gap analysis #1).
- Outbound IPv6 NDP NS-on-cache-miss (F180c follow-on).
