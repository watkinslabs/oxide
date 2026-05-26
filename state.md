# state — hand-off

Branch: F205-ssh-arm-channel-eof (PR #1287 open).
Workspace: spec-lint clean. Both arches pass `make smoke`.

## Where we are

Three SSH-related PRs this session:

- **#1285 F203 (merged)** — rt_sigframe layout flipped above
  handler SP on both arches; +128 B SysV red-zone skip on x86.
- **#1286 F204 (merged)** — ARM EL0-sync handler stashes user
  x9 in a stack preamble before `mrs x9, esr_el1`.
- **#1287 F205 (in flight)** — diagnostic + four
  Linux-correctness fixes. ARM SSH now streams shell output back
  reliably; channel close occasionally succeeds (sometimes EXIT 0
  in ~6 s) but most runs still time out at 30 s.

## F205 — what landed so far

1. `sys_pselect6` honors its sigmask argument; restore-on-return
   mirrors Linux's `restore_user_sigmask` / TIF_RESTORE_SIGMASK.
2. `sys_select` returns -EINTR when a deliverable signal is
   pending, so the kernel actually reaches signal delivery.
3. `sys_exit` drops the exiting task's fd_table Arc before
   posting SIGCHLD. Linux does this in `do_exit → exit_files`.
4. `fire_clone_hook` in vfs/file.rs, fired from
   FdTable::fork_clone / dup / dup_min / dup2. Pipe registers a
   clone-side counterpart that bumps writers/readers per
   duplicated reference. Without it, fork_clone bumped Arc<File>
   refcount but pipe open count stayed at 1 → POLL_HUP never
   propagated.

Diagnostic surface (`debug-ssh` feature, off by default):
- per-syscall nr/rv trace (filtered to skip the noisiest callers).
- rt_sigaction, rt_sigprocmask, rt_sigtimedwait, signalfd4.
- sys_exit + signal_child_exit + sys_wait4.
- pipe_close_hook + select / pselect6.
- deliver / deliver-masked / deliver-none at the dispatch tail.
- Helper module `kernel/src/syscalls/signal_trace.rs` keeps
  signal.rs under the 1000-line cap.

## What the trace pins down next

dropbear-aarch64's conn handler (tid 4128 in the trace) sits with
`mask=0x10000` (SIGCHLD blocked) and uses **plain pselect6 with
sigmask_pair=NULL** for its main blocking wait. It does NOT use
rt_sigtimedwait or signalfd4 for SIGCHLD detection — only the
dropbear master listener (tid 4126) calls rt_sigtimedwait, and
only 3 times during the SSH window.

The shell-stdout pipe's `writers` count never reaches 0 after the
shell child exits. Trace shows post-shell-exit pipe_close events:

    pipe_close writer prev=2 readers=2   (writers 2→1)
    pipe_close writer prev=2 readers=2   (writers 2→1)
    pipe_close reader prev=2 writers=2   (readers 2→1)

So three of the six pipe-end Arcs drop, but writers stays at 1.
That stray write-end Arc keeps `pipe.poll() & POLL_HUP == 0` and
dropbear's pselect never sees the EOF.

Candidates for the stray reference, ordered by likelihood:

1. **dup2 / fork interaction**: the child's dup2(write_end_fd, 1)
   fires the new clone hook (writers++), then close(write_end_fd)
   fires close hook (writers--). Sequence is balanced in theory,
   but if the close-hook path during execve's CLOEXEC sweep
   drops only the slot reference without the matching `fire`,
   the books slip by 1. Audit `close_on_exec` in
   `crates/kernel/vfs/src/fdtable.rs` — it sets `g.files[i] =
   None` which fires drop → close_hook, fine, but verify nothing
   bumped via clone-hook is missed.

2. **execve fd setup**: ELF loader / execve may dup the pipe
   ends into the new program's fd_table separately from
   fork_clone. If those calls don't go through dup_min /
   fd_table.alloc, the clone-hook side balance breaks. Audit
   `kernel/src/syscalls/execve.rs` near the stdin/stdout/stderr
   setup.

3. **dropbear holding an extra ref**: dropbear-aarch64 might
   keep an internal copy of the write-end fd in a chansess
   struct field used for an out-of-band ack channel. Less
   likely (would be the same source/binary on x86 too) but
   easy to rule out by adding a per-fd open-count probe.

Quickest next step: extend `pipe_close_hook` to also log the
PipeInode's `ino` field so we can correlate which pipe each
event refers to. Right now the events smear across three pipes
in one batch.

## Reliability today

- x86 SSH: reliable, ~5.7 s, exit 0.
- ARM SSH: streams shell output reliably; channel close races at
  ~1/5 success rate in cold-boot tests. The 4/5 failures stall
  at the 30 s SSH client timeout, then dropbear-aarch64 logs
  `Disconnect received`. Suggests a true race in pipe refcount
  vs. dropbear's select-loop polling cadence, not a missing
  syscall.

## Repro

    pkill -f qemu-system; rm -f /tmp/uart.sock /tmp/qa.log
    setsid bash -c 'OXIDE_QEMU_UART_SOCK=/tmp/uart.sock \
        OXIDE_QEMU_HEADLESS=1 \
        exec make qemu-arm FEATURES="debug-ssh" \
        > /dev/null 2>&1 < /dev/null' &
    until [ -S /tmp/uart.sock ]; do sleep 1; done
    socat -u UNIX-CONNECT:/tmp/uart.sock OPEN:/tmp/qa.log,creat,trunc &
    until ss -lnt | grep -q 2222; do sleep 5; done
    time timeout 30 sshpass -p swordfish ssh \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -p 2222 alice@127.0.0.1 'echo HELLO'
    # → HELLO prints; ~1-in-5 EXIT 0 at ~6 s; else EXIT 124.
    grep -aE "pipe_close|sys_exit tid=4129" /tmp/qa.log

`grep -a` mandatory (UEFI bytes confuse grep file-type detection).

## Out of scope

- Linux-shape sigcontext rework (full GP+SIMD save in the
  rt_sigframe). F203 layout fix is enough for dropbear's case.
- Early-boot bare3 ARM permission fault at far=0x7ffffffbd000
  elr=0x4001b0 — unrelated; pre-existing.
