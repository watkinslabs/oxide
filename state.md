# state — hand-off

Branch: F205-ssh-arm-channel-eof (PR #1287 open, lots of commits).
Workspace: spec-lint clean. Both arches pass `make smoke`.

## Session score this run

Eight merged + open fixes touching the syscall path, signal
delivery, fd lifecycle, ARM-asm correctness, and spec/CLAUDE
documentation. Specifically:

1. **#1285 F203 (merged)** — rt_sigframe layout flipped above
   handler SP on both arches; +128 B SysV red-zone skip on x86.
2. **#1286 F204 (merged)** — ARM EL0-sync handler stashes user
   x9 in a 16 B stack preamble before `mrs x9, esr_el1`. Fixed
   resolved-and-retried demand-page faults clobbering user x9.
3. **#1287 F205 (in flight)** — large cleanup PR adding:
   - `sys_pselect6` honors sigmask argument (was a no-op shim).
   - `sys_select` returns -EINTR when a deliverable signal pends.
   - `sys_exit` drops fd_table Arc before mark_done (Linux
     `do_exit → exit_files` parity).
   - **inotify double-decrement removed** — `vfs_close_notify`
     was decrementing pipe writers/readers on top of pipe.rs's
     `pipe_close_hook`, underflowing on first close. Big find.
   - **a5 plumbing** — standard SysV C-ABI dispatch fn fits only
     5 args after nr; a5 was silently dropped on BOTH arches. Now
     read from the per-arch saved frame via
     `crate::syscalls::syscall_a5::read()`. sys_pselect6's sigmask
     was the visible victim.
   - **deliver returns sig on aarch64** — the ARM SVC restore asm
     ends with `ldr x0, [sp, #0xc8]`, clobbering whatever
     `frame.gp[0]` held. `oxide_syscall_dispatch` now returns `sig`
     when it set up a handler so the retval slot seeds user x0 =
     handler's first AAPCS64 arg.
   - **Signum enum extended** to all 31 standard POSIX signals;
     `signal_dispatch.rs` (new module, extracted from signal.rs
     for `08§7`) uses typed Signum + named SIG_DFL/SIG_IGN consts
     — zero magic signal-numbers per CLAUDE.md `07§5`.
   - **`debug-ssh` Cargo feature** + `signal_trace` helpers —
     much narrower than `debug-sched`, won't flood the PL011 UART
     on ARM. Trace surface: rt_sigaction, rt_sigprocmask,
     rt_sigtimedwait, signalfd4, deliver / deliver-masked,
     pipe_create / pipe_close, sys_exit drop, select ready /
     EINTR / timeout, syscall nr/rv (filterable).
   - **`docs/54-asm-correctness.md`** (new) — assembly+ABI
     checklist covering BOTH x86_64 and aarch64. CLAUDE.md TOC
     points to it. Quick-ref table for typed constants
     (Signum / Errno / NR_FOO / OpenFlags / POLL_*) included.

`make smoke` PASS both arches. x86 SSH `echo HELLO` still
returns exit 0 in ~6 s. ARM SSH streams shell output back
correctly (the kernel-side pipe/POLL/EOF machinery now works
identically on both arches).

## Remaining bug

ARM SSH client times out at 30 s when waiting for CHANNEL_CLOSE.

`debug-ssh` trace shows the asymmetry precisely:
- dropbear-aarch64 (the static-PIE musl-pthread binary) blocks
  SIGCHLD in steady-state via musl's `__block_all_sigs`/
  `__restore_sigs` cycle. Mask = 0x10000 (SIGCHLD bit) throughout.
- It calls `pselect6(..., NULL sigmask)` — strict POSIX semantics
  leave the mask intact, SIGCHLD stays blocked, handler never
  fires, no `wait4` reaps the shell child, no
  CHANNEL_EXIT_STATUS / CHANNEL_CLOSE goes out.
- x86 dropbear (statically linked WITHOUT pthread) has mask=0
  throughout; SIGCHLD delivers naturally; whole flow works in ~6 s.

The kernel-side framing (pipe writer/reader counting, sys_exit
fd_table drop, POLL_HUP propagation, select-ready-on-EOF) is now
correct — the trace confirms `select ready=2` fires post-shell-
exit and `signal_child_exit` posts SIGCHLD into dropbear's
sigpending bitmap. The bit just never delivers because mask
blocks it.

## Three live hypotheses for the last mile

1. **Build-side: dropbear-aarch64 binary was compiled against
   a musl that disables SIGCHLD-via-pthread-sigmask-restore**
   — i.e., this specific binary may be effectively broken on
   real-iron Linux too. Recompile without pthread; or use a
   different dropbear build per arch in `vendor/dropbear/`.

2. **Force-deliver SIGCHLD despite mask (kernel POSIX
   divergence).** Tested in this session — *appears* to deliver
   (deliver_arm trace fires, frame.elr_el1 = sesssigchild_handler,
   `return-with-sig` confirms dispatch returns the right state to
   the asm restore) — **but the user-mode handler never actually
   executes**: no `write` (the handler's first syscall, the self-
   pipe wakeup), no `rt_sigreturn`. dropbear's next syscall after
   delivery is `read` from the shell-stdout pipe — exactly what
   the main `pselect6` loop would do, not what the handler would do.
   Single-stepping with the qemu MCP is the way to confirm whether
   eret actually lands at handler. Hypothesis 2a: handler's
   stack-frame prologue `stp x29, x30, [sp, #-208]!` faults on an
   un-grown user-stack page below new_sp and the fault path
   doesn't actually deliver SIGSEGV (no [FAULT] trace) but also
   doesn't run the handler. Hypothesis 2b: TLS access (`ldr x0,
   [adrp+#3616]`) at handler entry returns garbage causing the
   subsequent stack-canary store to crash silently.
3. **Auto-reap kernel-side.** Detect "task has SIGCHLD pending +
   masked + has a zombie child" and force-call wait4. This
   propagates POLL_HUP correctly (already happens with this
   PR's fixes) but doesn't help send CHANNEL_EXIT_STATUS because
   dropbear's `chansess->exit_pending` flag is set inside the
   handler. So dropbear still won't know the shell's exit code.

Next session likely lands hypothesis 2 with qemu MCP single-step,
or pivots to (1) by rebuilding dropbear-aarch64 without pthread.

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
    # → HELLO prints; EXIT 124 at 30 s; dropbear logs
    #   Disconnect received after the client gives up.

`grep -a` mandatory on `/tmp/qa.log` — UEFI boot bytes confuse
grep file-type detection. Per `docs/54§6`.

## See also

- `docs/54-asm-correctness.md` — checklist for new asm patches.
- CLAUDE.md "Quick reference — typed constants" — magic-number
  ban list.
- F203/F204 commit messages — the prior two patches in this
  three-PR sequence.
