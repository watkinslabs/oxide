# state — hand-off

Branch: F205-ssh-arm-channel-eof (PR #1287 open).
Workspace: spec-lint clean. Both arches pass `make smoke`.

## Where we are

Three SSH-related PRs landed this session:

- **#1285 F203 (merged)** — rt_sigframe layout flipped above
  handler SP on both arches; +128 B SysV red-zone skip on x86.
- **#1286 F204 (merged)** — ARM EL0-sync handler stashes user
  x9 in a stack preamble so `mrs x9, esr_el1` no longer
  permanently corrupts the user x9 across resolved-and-retried
  demand-page faults.
- **#1287 F205 (in flight)** — large diagnostic + multi-fix push
  for ARM SSH channel close. Lands the `debug-ssh` cargo feature
  with targeted trace inside select/wait4/exit/signal-child/
  rt_sig{action,procmask}/pipe-close. Also adds three real
  Linux-correctness fixes (each likely a separate concern in a
  future-better-tested kernel but harmless on x86):

  1. `sys_pselect6` now honors its sigmask argument (was a
     pass-through to sys_select). Atomic swap on entry; restore
     on exit unless a signal is deliverable, mirroring Linux's
     restore_user_sigmask / TIF_RESTORE_SIGMASK.
  2. `sys_select` inner loop now returns -EINTR when a
     deliverable signal is pending. Without it the loop sits in
     tick_yield forever when the only thing breaking the wait
     is a signal.
  3. `sys_exit` now drops the exiting task's fd_table Arc
     before posting SIGCHLD. Linux closes a process's open
     files at exit (do_exit → exit_files); we previously left
     them alive until reap.
  4. New `fire_clone_hook` in vfs/file.rs, fired from
     FdTable::fork_clone / dup / dup_min / dup2. Pipe registers
     a clone-side hook (mirror of the close hook) that bumps
     writers/readers per duplicated reference. Without this,
     fork_clone bumps Arc<File> refcount without bumping the
     pipe's open count, so closing one copy doesn't fire the
     File::drop close hook and POLL_HUP never propagates.

These four fixes get ARM SSH to:
  - stream `echo HELLO; id; uname -a` output back to the client,
  - reach POLL_IN / POLL_HUP propagation parity with x86,
  - but the SSH client still times out at 30 s.

## Smoking gun for the residual hang

`grep ssh-trace` shows tid=4128 (dropbear conn handler) sits in
`deliver-masked pending=0x10000 mask=0x10000` forever after the
shell child exits. dropbear-aarch64's `sigmask` permanently has
SIGCHLD blocked (bit 16). Compare x86 dropbear, which has
mask=0 throughout and delivers SIGCHLD normally.

The `rt_sigprocmask` trace for tid 4128 shows the actual
sequence dropbear-aarch64 uses:

    how=2 (SETMASK) new=fffffffc7ffbfeff   "block-most"
    how=2 (SETMASK) new=0000000000010000   "block SIGCHLD only"
    how=0 (BLOCK)   new=fffffffc7ffbfeff   "block-most again"
    how=2 (SETMASK) new=0000000000010000   "block SIGCHLD"
    … repeats forever …

dropbear-aarch64 **never sets mask=0**. Compare x86 dropbear:
zero rt_sigprocmask calls on the conn handler tid; mask stays
at 0; SIGCHLD delivers normally; session closes in ~6 s.

The pselect6 trace shows all 38 calls during the SSH window
use `sigmask_pair=0` (NULL). dropbear-aarch64 calls
`pselect6(..., NULL)`. So even with F205's pselect6 sigmask
swap implementation, there's no sigmask to swap in.

Conclusion: dropbear-aarch64 is built for a model where
SIGCHLD is detected via something OTHER than handler delivery —
likely `sigtimedwait` / `rt_sigtimedwait` (slot 128, we have a
basic impl) or `signalfd` (slots 282 / 289). dropbear polls
that synchronous source from its main pselect loop instead of
relying on async delivery.

## Next session — start here

1. Add `debug-ssh` trace inside `sys_rt_sigtimedwait` and
   `sys_signalfd*`. Run ARM SSH and see whether dropbear-aarch64
   calls either. If yes, the dropbear ↔ kernel ABI side of the
   hang is in that impl — verify SIGCHLD gets popped properly
   when the signal is pending-and-blocked (Linux's behavior is
   to dequeue from the task's pending set while still leaving
   the mask intact for unrelated delivery).
2. If dropbear-aarch64 calls neither, dump the actual syscalls
   it makes during the post-exec window (add `debug-ssh` to the
   nr/rv trace at mod.rs:885). The smoking gun might be a
   different mechanism altogether — `rt_sigqueueinfo`,
   `pidfd_open`, an epoll edge, etc.
3. Once the dropbear-aarch64 wakeup mechanism is identified,
   wire it through our kernel and SIGCHLD will deliver, wait4
   will reap, and CHANNEL_EOF will go out.

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
        -p 2222 alice@127.0.0.1 'echo HELLO; id; uname -a'
    # → HELLO + id + uname print; EXIT 124 at 30 s; dropbear
    #   logs Disconnect received after the client gives up.
    grep -a "ssh-trace: deliver" /tmp/qa.log | tail -5
    # → all deliver-masked, none successful.

`grep -a` mandatory — early UEFI lines contain bytes that make
grep treat the log as binary.

## Out of scope

- Same Linux-shape sigcontext rework (full GP+SIMD save in the
  rt_sigframe). F203 layout fix is enough for dropbear's case
  but not for general POSIX semantics under preemption.
- Early-boot bare3 ARM permission fault at far=0x7ffffffbd000
  elr=0x4001b0 — unrelated to SSH; pre-existing.
