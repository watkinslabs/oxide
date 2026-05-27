# state — hand-off

Branch: F205-ssh-arm-channel-eof (PR #1287 open, lots of commits).
Workspace: spec-lint clean. Both arches pass `make smoke`.

## What I shipped this session

Three SSH-targeted PRs and one large supporting infrastructure
landing:

- **#1285 F203 (merged)** — rt_sigframe layout flipped above
  handler SP on both arches; +128 B SysV red-zone skip on x86.
  Fixed `Aiee, segfault!` at dropbear-x86_64 SSH teardown.
- **#1286 F204 (merged)** — ARM EL0-sync handler stashes user
  x9 in a 16 B stack preamble before `mrs x9, esr_el1`. Fixed
  resolved-and-retried demand-page faults clobbering user x9;
  dropbear-aarch64 sha256_compress NULL+0x24 crash gone.
- **#1287 F205 (open, 7 commits)** — large cleanup PR adding:
  - `sys_pselect6` honors sigmask argument (was a no-op shim).
  - `sys_select` returns `-EINTR` when a deliverable signal pends.
  - `sys_exit` drops fd_table Arc before mark_done — Linux
    `do_exit → exit_files` parity. Without this, pipe POLL_HUP
    never propagated.
  - **inotify double-decrement removed** — `vfs_close_notify`
    was decrementing pipe writers/readers on top of pipe.rs's
    `pipe_close_hook`, underflowing on first close.
  - **a5 plumbing** — standard SysV-ABI dispatch fits only 5
    args after nr; a5 was silently dropped on BOTH arches. Now
    read from the per-arch saved frame via
    `crate::syscalls::syscall_a5::read()`. sys_pselect6's
    sigmask was the visible victim.
  - **deliver returns sig on aarch64** — the ARM SVC restore
    asm ends with `ldr x0, [sp, #0xc8]`, clobbering whatever
    `frame.gp[0]` held. `oxide_syscall_dispatch` now returns
    `sig` when it sets up a handler so the retval slot seeds
    user x0 = handler's first AAPCS64 arg.
  - **Signum enum extended** to all 31 standard POSIX signals;
    `signal_dispatch.rs` (new module, extracted from signal.rs
    for `08§7`) uses typed Signum + named SIG_DFL/SIG_IGN
    consts — zero magic signal-numbers per CLAUDE.md `07§5`.
  - **`debug-ssh` Cargo feature** with full trace surface:
    rt_sigaction, rt_sigprocmask, rt_sigtimedwait, signalfd4,
    deliver / deliver-masked, pipe_create / pipe_close,
    sys_exit drop, select ready / EINTR / timeout, syscall
    nr/rv (tid-tagged, filterable).
  - **`docs/54-asm-correctness.md`** — assembly+ABI checklist
    covering BOTH x86_64 and aarch64. CLAUDE.md TOC points to
    it; quick-ref table for typed constants
    (Signum / Errno / NR_FOO / OpenFlags / POLL_*) added.
  - `set_current_svc_frame` hal-aarch64 helper exposed for
    future per-task dispatch-frame plumbing.

x86 SSH `echo HELLO` returns exit 0 in ~6 s (unchanged).
ARM SSH **streams** the shell command output back correctly
(`echo HELLO; id; uname -a` all visible to the client); the
kernel-side pipe-EOF and POLL_HUP machinery is now correct on
both arches.

## Remaining bug — dropbear-aarch64 binary architectural

ARM SSH client times out at 30 s waiting for CHANNEL_CLOSE.

`debug-ssh` trace shows precisely:
- dropbear-aarch64 (static-PIE, **musl-pthread** linked, 36
  pthread symbols) blocks SIGCHLD in steady-state via musl's
  `__block_all_sigs`/`__restore_sigs` cycle. The save buffer
  always reads back `0x10000`, so mask stays SIGCHLD-blocked
  throughout the session.
- dropbear calls `pselect6(..., NULL sigmask)` — strict POSIX
  semantics leave the mask intact. SIGCHLD stays blocked.
  Handler never fires; `wait4` is never called for the shell
  child; `chansess->exit_pending` is never set inside dropbear
  (only the handler sets it); CHANNEL_EXIT_STATUS + CHANNEL_
  CLOSE never go out.
- x86 dropbear (statically linked WITHOUT pthread; 0 pthread
  symbols) has mask=0 throughout; SIGCHLD delivers naturally;
  whole flow works in ~6 s.

Tried in this session and discarded:
- **POSIX-violating SIGCHLD mask bypass.** Re-enabled
  `take_lowest_pending` to deliver SIGCHLD even when masked if
  a user handler is installed. `deliver_arm` fired and set
  `frame.elr_el1 = sesssigchild_handler`, `frame.x30 =
  restorer`, `frame.sp_el0 = new_sp`. `return-with-sig` trace
  confirmed the dispatch's u64 retval = sig and all frame
  fields were intact at the dispatch's last Rust instruction.
  Yet the user-mode handler never executes a `write` (the
  handler's first syscall, the self-pipe wakeup) and never
  issues `rt_sigreturn`. The very next syscall is dropbear's
  main-loop `read(stdout_pipe)` — i.e. dropbear continues from
  `saved_pc` (= musl's _exit wrapper), not from the handler at
  0x10011af8. This implies the eret-to-handler doesn't actually
  land in user mode at the handler PC. We did not single-step
  through to confirm (qemu MCP would be the next tool).
- **Per-task `oxide_svc_frame_base` save/restore across
  `oxide_context_switch`.** Theory: another task's SVC entry
  during a `schedule()` race overwrites the global, so
  `deliver_arm`'s `current_svc_frame()` reads the wrong frame.
  The asm change broke kthread bring-up (`new_kernel` contexts
  have `svc_frame_base=0`, the restore zeroed the global on
  first kthread switch-in, boot wedged at "keymap loaded").
  Reverted. The right fix probably stores the frame ptr in the
  Task struct at SVC entry rather than in a global at all.

## Three live hypotheses for the last mile

1. **Rebuild dropbear-aarch64 without pthread.** musl-cross's
   aarch64 toolchain links pthread by default; the x86 build
   doesn't link pthread and works fine. Either:
   - rebuild against a non-pthread musl-aarch64, OR
   - track down which configure flag/autoconf check pulls
     pthread in (config.h has zero pthread defines) and disable.
2. **qemu MCP single-step the eret.** The `return-with-sig`
   trace shows the right frame state at dispatch exit on
   aarch64 — but the user doesn't enter the handler. Set a
   breakpoint at `eret` in `oxide_lower_sync_restore`, step
   once, check the live `ELR_EL1` register and the user PC.
   That's the definitive proof of what eret actually does.
3. **Per-task dispatch-frame ptr in Task struct.** Reattempt
   the svc_frame_base race fix without going through context
   switch (which broke kthreads). Write the frame ptr to a new
   `Task.svc_frame_base: AtomicU64` slot at SVC entry; read
   from it in `deliver_arm`. Kthreads default to 0 and never
   touch the slot.

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
    # → HELLO + id + uname print; EXIT 124 at 30 s;
    #   dropbear logs Disconnect received after the timeout.
    grep -a "ssh-trace: deliver-masked tid=4128" /tmp/qa.log | wc -l
    # → many; SIGCHLD pending+blocked forever.

`grep -a` mandatory on `/tmp/qa.log` — UEFI boot bytes confuse
grep file-type detection. Per `docs/54§6`.

## See also

- `docs/54-asm-correctness.md` — checklist for new asm patches
  (both arches).
- CLAUDE.md "Quick reference — typed constants" — magic-number
  ban list.
- F203/F204 commit messages — the prior two PRs.
