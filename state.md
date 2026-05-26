# state — hand-off

Branch: F203-ssh-channel-eof (next bug; no fix landed yet).
Workspace: spec-lint clean.

## Where we are

Two PRs landed this session: #1281 (F201 pipe + pty `poll()`)
and #1282 (F202 `sys_select` consults `inode.poll()`). The
combination took the SSH exec channel from "hangs forever +
Aiee segfault" to actually returning shell output to the client:

    $ ssh -p 2222 alice@127.0.0.1 'echo HELLO; id; uname -a'
    HELLO
    uid=1000(alice) gid=1000 groups=1000,10(wheel),100(users)
    Linux oxide 5.15.0-oxide #1 SMP PREEMPT oxide v0.1.0 x86_64 GNU/Linux

## Open — F203 candidates

1. **Channel never closes.** ssh client hangs waiting for
   CHANNEL_EOF/CHANNEL_CLOSE after the last output arrives.
   Likely pipe writers→0 (POLL_HUP) isn't producing the EOF read
   that dropbear's session pump needs to emit CHANNEL_EOF.
   Inspect `crates/kernel/fs/src/pipe.rs` close-hook (`writers
   .fetch_sub`) plus the `read()` path that returns Ok(0) when
   writers==0 — verify it actually unblocks a parked reader.

2. **"Aiee, segfault!"** prints on busybox sh exit after the
   exec command finishes. Trace under
   `make qemu-x86-debug FEATURES=debug-syscall,debug-irq` and
   filter `[FAULT] sigsegv` to capture rip/cr2. Probably either
   (a) wait4 path on shell reaping subshell `uname` child, or
   (b) sys_exit_group teardown of the last user thread.

3. **N-1 commands rule:** each test run delivers one more
   command than the previous build; smells like a buffer-drain
   off-by-one in dropbear's exec → ssh-socket forwarder. Could
   be a side effect of (1).

## Reproducer (literal first command for next session)

    make qemu-x86 OXIDE_QEMU_HEADLESS=1 > /tmp/q.log 2>&1 &
    until ss -lnt | grep -q 2222; do sleep 1; done
    sshpass -p swordfish ssh -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null -p 2222 \
      alice@127.0.0.1 'echo HELLO'

Expect HELLO + hang. Then `tail -50 /tmp/q.log` for the segfault
print.

## Out-of-scope (deferred for later PRs)

- TCP_INFO field completeness past tcpi_total_retrans (F188).
- SCM_RIGHTS over SOCK_STREAM (F189 covers SOCK_DGRAM only).
- AF_NETLINK ROUTE / sock_diag completeness (D45 gap analysis #1).
- Outbound IPv6 NDP NS-on-cache-miss (F180c follow-on).
