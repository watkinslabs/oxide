# state — hand-off

Branch: F203-ssh-channel-eof (in flight; diagnostic landed).
Workspace: spec-lint clean.

## Where we are

F201 + F202 merged in #1281/#1282. SSH exec channel returns
real shell output (`echo HELLO; id; uname -a` works) but the
session ends with **`Aiee, segfault!`** from dropbear and the
ssh client hangs waiting for CHANNEL_EOF/CHANNEL_CLOSE.

## What this PR lands (F203 diagnostic only)

Added `[FAULT] catchable-sigsegv tid=… rip=… cr2=… handler=…`
klog under `debug-irq` inside
`crates/kernel/mm-pmm/src/user_as/signal.rs::try_deliver_sigsegv_via_handler_x86`.
Without it, the user-mode handler-rewrite path was a black
box — the terminate-path `[FAULT]` dump only fires when the
task is going to die, so a process whose SIGSEGV handler
catches the fault leaves zero kernel-side trace.

## What the diagnostic captured

    [FAULT] catchable-sigsegv tid=4132 rip=0x0 rsp=0x7ffffffef990
                              cr2=0x0 handler=0x40f02b

dropbear's connection-handler process **jumps to NULL** —
`rip=0` on instruction fetch, `cr2=0`. dropbear's
`sigsegv_handler` (at `0x40f02b` in `dropbearmulti-x86_64`)
catches it, prints `Aiee, segfault!`, exits the connection.

## Open — F204 candidates

Find the dropbear call site that lands at NULL. Two leads:

1. **Indirect call through uninitialized slot.** dropbear
   ChanType vtable has optional fn pointers (closehandler,
   reqhandler, …). One could be NULL where a caller doesn't
   guard. Audit `svr-chansession.c` chantype_sesschan and
   the `channel_close` / `cleanupchansess` path.

2. **Signal handler return path.** If a *prior* signal
   (SIGCHLD from the shell child) delivered with a bad
   restorer, the user handler's `ret` could pop NULL. Verify
   `deliver_x86` in `crates/kernel/fs/src/sig_dispatch.rs` —
   restorer comes from `sa.restorer` set via rt_sigaction; if
   dropbear's musl set it to 0 for some signal, the handler
   returns to 0.

   Repro under debug-irq + debug-sched will show every
   `sig: deliver sig=…` line — match against the catchable
   fault tid to see if a signal was delivered just before.

## Repro

    make qemu-x86 OXIDE_QEMU_HEADLESS=1 FEATURES=debug-irq \
        > /tmp/q.log 2>&1 &
    until ss -lnt | grep -q 2222; do sleep 1; done
    sshpass -p swordfish ssh -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -p 2222 \
        alice@127.0.0.1 'echo HELLO'
    grep "FAULT\|Aiee" /tmp/q.log

## Out-of-scope (deferred)

- TCP_INFO field completeness past tcpi_total_retrans (F188).
- SCM_RIGHTS over SOCK_STREAM (F189 covers SOCK_DGRAM only).
- AF_NETLINK ROUTE / sock_diag completeness (D45 gap analysis #1).
- Outbound IPv6 NDP NS-on-cache-miss (F180c follow-on).
