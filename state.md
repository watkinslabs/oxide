# State 2026-05-11

## Branch
`F04-serial-getty` — PR #1010 open. Stacks on PR #1009 (B13 asm fix, already merged via this branch's base).

## What shipped this run

Three layered fixes that together unblock the B12 rcS-to-getty wedge:

1. **#1009 (B13)** `oxide_syscall_entry` asm bug: user-ABI args (rdi/rsi/rdx/r10/r8/r9) were restored from the saved frame, then clobbered by the SysV C call to `oxide_x86_arm_singlestep`. musl `open()` returned -1 with garbage errno → busybox printed `"can't open '/etc/init.d/rcS': %m"`. Fix: save the 6 arg regs across the singlestep C call.

2. **#1010 (F04)** `sys_wait4(-1)` now returns `-ECHILD` via new `registry::has_children(parent)` when caller has zero live children. Every shell's drain loop `do { pid = waitpid(-1); ... } while (pid >= 0)` needs ECHILD to exit. Without it, hush blocked forever after reaping its first child and rcS never advanced past the first mount command.

3. **#1010** inittab now spawns `/sbin/getty -L 115200 ttyS0 vt100` (instead of tty1 getty) so the login banner is observable on the qemu-mcp serial path.

4. **#1010** rcS smoke list drops `ptrace_smoke` + `ptrace_singlestep_smoke` — the SIGSTOP/SIGTRAP race wedges the script. Real PTRACE_SINGLESTEP TF/SS arming is a follow-up.

## Verified at boot (x86_64)

- `cargo run -p xtask -- spec-lint` clean.
- `make x86` + `make arm` green.
- x86 qemu boot reaches rcS execution end-to-end: 4 mounts (proc/sysfs/tmpfs/devpts) + hostname + ifconfig + oxide-smokes (bare3, sem/msg/mq smoke, mprotect, hello_dyn) all run.
- hush exits; init reaps via `wait4 reap=4100`; init fork+execs `/sbin/getty`.
- Issue banner `oxide Linux on /dev/ttyS0` writes to serial via writev.
- `oxide login: ` writev IS called (verified with sys_writev probes) — bytes reach klog::write_raw → UART sink. The prompt arrives **with timing-sensitivity**: with kernel-side debug probes present the bytes appear promptly; without them the prompt-writev fires after a longer delay (likely scheduling/tty-output queueing).

## Open work

### Login prompt timing (NEXT)
`/sbin/getty` calls 4 writev() to print the issue, then a 5th writev for `"oxide login: "`. The 5th is delayed by scheduling — appears immediately when klog::write_raw probes add per-syscall delay, not without. Suspect either:
  - console_emit buffers through fbcon softirq queue that drains only on yield
  - getty schedules between writevs in a way that doesn't wake quickly without artificial work

Repro: `make x86 && qemu_start && qemu_run_until login:` → timeout. Adding any klog probe in sys_writev makes the prompt appear within a few seconds.

### Real PTRACE_SINGLESTEP
F49+F50+F51 framework exists (singlestep flag, TF arming, SIGTRAP delivery) but the SIGSTOP/SIGTRAP signal-delivery race makes ptrace_singlestep_smoke hang. Skipping the test in rcS for now; real fix needs to coordinate the ATTACH-induced SIGSTOP with the post-SINGLESTEP wake so SIGTRAP fires correctly.

### Display visibility on GTK / Serial input echo (still parked)
Unchanged from prior state.

## Followups ready to stack

- aarch64 SVC entry: audited in #1009 and structurally safe (retval stored to memory before singlestep C call; all regs restored from frame after). No fix needed.
- F03+ keymap follow-ups (mouse drain, loadkeys helper).
- D-spec for keymap text format (formalize grammar in docs/46).

## First task next session

```sh
# Investigate the writev-without-probes timing issue.
# Hypothesis: kernel needs a yield point between back-to-back syscalls
# so userspace can re-enter the next syscall. Probe sched::live::schedule
# to see if it's called between getty's writevs.
make x86 && cargo run -p xtask -- spec-lint  # baseline clean
```

Alt pivots:
- Real PTRACE_SINGLESTEP work (then re-enable the ptrace smokes).
- F05+ network features once the boot chain is solid.

## Useful pointers

- wait4 ECHILD: `kernel/src/syscalls/mod.rs:235-250` (`has_children` gate).
- sys_writev path: `kernel/src/syscalls/fs.rs:718`.
- ConsoleInode::write → console_emit alias for klog::write_raw at `kernel/src/dev/console.rs:24`.
- Syscall asm: `crates/arch/hal-x86_64/src/syscall.rs:175-205` (singlestep save/restore block).
