# state — hand-off

Branch: F201-pty-stdio-relay (in flight → PR pending).
Workspace: spec-lint clean, x86 smoke 16s.

## Endgame this session: working SSH login

Auth through `Password auth succeeded` is in. Exec-channel relay
through the dropbear→shell pipe still drops bytes: the ssh client
sees no output and connection hangs. After client disconnect the
qemu log shows `Aiee, segfault!` (busybox sh / dropbear child
SIGSEGV) which is the next layer to chase.

## What this PR lands

1. **PipeInode::poll()** — was inheriting the always-ready
   `POLL_IN|POLL_OUT` default, so `select(read_fd)` returned
   immediately even with an empty buffer; userspace nonblock
   readers spun on EAGAIN. Now reflects Linux pipe(7):
   `POLL_IN` when buffered or writer-EOF; `POLL_OUT` when room
   and at least one reader; `POLL_HUP` when readers==0.
2. **PtyMasterInode / PtySlaveInode poll() + read_nonblock()** —
   same gap on the pty side. Master/slave now report `POLL_IN`
   only when the peer→queue has bytes; readers honor O_NONBLOCK
   via EAGAIN. Without this dropbear's session pump
   (`select(master_fd) + read(master_fd)`) sees ready, reads
   EAGAIN, repeats — busy loop or spurious wakeup, never relay.

## Verified

- spec-lint clean.
- x86 smoke reaches login in 16s with both poll changes in.
- ssh handshake + password auth still complete (`Password auth
  succeeded for 'alice'`).

## Open — next bug to chase (F202)

After `Password auth succeeded`, the exec channel never delivers
shell output to the ssh client. On client-side disconnect the
guest prints **`Aiee, segfault!`** — busybox sh (or a dropbear
child) is taking a SIGSEGV. No `[debug-fault]` traces in the
default klog gate-set so the faulting RIP/cr2 is invisible. Next
steps:

- Enable `debug-fault` (or whatever subsystem owns user
  page-fault klog) cargo feature on the smoke profile so the
  segfault prints faulting address + RIP + tid.
- Re-run `ssh ... 'echo HELLO'`; capture the fault site.
- If it's busybox: check the noptycommand path
  (`spawn_command → fork → dup2(pipe) → execve("/bin/sh","-c",
  "echo HELLO")`). Verify dup2 of pipe write end to fd 1 sticks
  through execve, and that the shell's first `write(1, ...)`
  goes to the pipe (not a closed/garbage fd).
- If it's dropbear: stderr pipe handling or child-reaper race.

## Out-of-scope (deferred for later PRs)

- TCP_INFO field completeness past tcpi_total_retrans (F188).
- SCM_RIGHTS over SOCK_STREAM (F189 covers SOCK_DGRAM only).
- AF_NETLINK ROUTE / sock_diag completeness (D45 gap analysis #1).
- Outbound IPv6 NDP NS-on-cache-miss (F180c follow-on).
