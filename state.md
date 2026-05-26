# state — hand-off

Branch: F205-ssh-arm-channel-eof (PR open).
Workspace: spec-lint clean.

## Where we are

Three SSH PRs landed this session:

- **#1285 F203 (merged)** — flipped the rt_sigframe layout on
  BOTH arches so saved-context lives at addresses ≥ handler-entry
  SP, plus skipped the 128 B SysV red-zone on x86. Fixed the
  `Aiee, segfault!` at dropbear-x86_64 SSH teardown.
- **#1286 F204 (merged)** — stashed user x9 in a 16-B stack
  preamble before the ARM EL0-sync EC dispatch clobbers it via
  `mrs x9, esr_el1`. Without this, every resolved-and-retried
  demand-page fault returned to userspace with x9 permanently
  set to 0x24 (data-abort EC). musl `sha256_compress` blew up
  immediately on dropbear-ARM because it keeps `x9 = sp+0x18`
  live across hundreds of instructions with no syscall.
- **F205 (this branch, PR open)** — adds `debug-ssh` cargo
  feature gating klog inside `sys_select`, `sys_wait4`, and
  `signal_child_exit`. **Narrow** enough not to flood the PL011
  UART on ARM. Pinpoints the remaining bug — does NOT yet fix it.

ARM SSH still hangs at channel close, but we now know exactly why.

## Diagnostic finding — smoking gun

x86 trace around shell exit (`echo HELLO`):

    ssh-trace: signal_child_exit child=4133 parent_tid=4132 parent_upgrade=1
    ssh-trace: select ready=1
    ssh-trace: select ready=2          ← pipe POLL_HUP added on next poll
    ssh-trace: wait4 reaped tid=4133 parent=4132
    ssh-trace: wait4 ECHILD parent=4132
    ssh-trace: select timeout
    [38] Exit (alice): Disconnect received

ARM trace around shell exit:

    ssh-trace: signal_child_exit child=4129 parent_tid=4128 parent_upgrade=1
    ssh-trace: select ready=1          ← repeats forever
    ssh-trace: select ready=1
    … (no `select ready=2`, no `wait4 reaped tid=4129`)

Same source binaries (dropbearmulti-{x86_64,aarch64}). The
difference is unambiguous: on ARM the kernel posts SIGCHLD into
dropbear's `sigpending`, but **dropbear's SIGCHLD handler never
runs**. Without it dropbear never issues `wait4` for the shell
child, the child stays zombie, its FdTable Arc stays live,
`pipe_close_hook` never decrements `writers`, the pipe-read fd
never reports POLL_HUP, dropbear's select keeps returning only
the socket as ready, and CHANNEL_EOF is never pushed to the SSH
client. After 30 s the client gives up and dropbear logs
`Disconnect received`.

## Next session — start here

The bug is between `signal_child_exit` (posts SIGCHLD bit) and
`take_lowest_pending` / `deliver_arm` (would jump into handler).
Things to check, in order:

1. **Is dropbear-ARM's sigactions[SIGCHLD-1].handler != 0 after
   the rt_sigaction call?** Add a `debug-ssh` klog in
   `sys_rt_sigaction` printing `(sig, new_handler)` when sig=17.
   If handler stays 0 on ARM, our rt_sigaction is dropping the
   write — that's the bug.
2. **Does `take_lowest_pending` see the SIGCHLD bit on ARM?**
   Klog the (pending, masked, deliver) trio at every syscall
   tail in mod.rs:928. If deliver==0 despite the bit being set,
   sigmask is hiding it.
3. **Does the SVC-tail signal-delivery code ever run for
   dropbear's tid on ARM?** Klog `[tid, sig]` at mod.rs:946
   match arm. If never fires after `signal_child_exit child=4129`,
   syscall-tail isn't reaching that code on ARM — likely an
   asm-path divergence (compare to x86 syscall_glue.asm exit).
4. **deliver_arm correctness post-F203:** spot-check that the
   re-laid sigframe path actually lands the user at the handler.
   `deliver_arm` rewrites `frame.elr_el1 = handler`. F204 fixed
   x9 clobber on aborts but the SVC path may have similar issues
   the F204 fix didn't cover.

Repro (need debug-ssh feature for the trace):

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
    # → HELLO prints; client EXIT 124 at 30 s; dropbear logs
    #   Disconnect received after that.
    grep -a "ssh-trace" /tmp/qa.log | tail -40

`grep -a` is required — the boot UEFI lines contain bytes that
make `grep` treat the file as binary.

## Out of scope for F205

- Same Aiee audit on a SIGSEGV handler that isn't catchable —
  F203 layout fix covers the rt_sigframe but not the actual user
  fault path (would need a Linux-shape sigcontext with full GP+
  SIMD save).
- Early-boot bare3 ARM permission fault at `far=0x7ffffffbd000
  elr=0x4001b0 sp_el0=0x7ffffffefd80` — unrelated to SSH; pre-
  existing; safe to ignore until smoke regression demands.
