# state.md — session hand-off

## Headline
**The ~90% nondeterministic boot heap corruption is FIXED and MERGED to main.**
Root cause: a KERNEL-STACK OVERFLOW. Kernel stacks were bare 16 KiB `Box<[u8]>`
heap allocs with NO guard page, so an overflow silently scribbled the adjacent
static-heap block (victim/timing varied by layout, masked by any allocator
change — the "wild write, unrelated victim" signature chased for weeks).

## What's fixed (C213, merged)
1. **Linux CONFIG_VMAP_STACK** — new `sched::kstack`: 16 KiB (THREAD_SIZE) mapped
   4 KiB-granular with an unmapped guard page below; replaces the 4 scattered
   `vec![0u8;16*1024]` stacks. Overflow now #PF/#DF at the culprit, not silent
   corruption. Frames via kmain-installed pmm hook (sched can't dep pmm).
   `sync::KStack` rank. `Task.stack: Option<GuardedStack>`.
2. **zram compressor init frame 27 KiB→152 B** — lzo `[Spinlock;256]`→Vec; zstd
   Dictionary boxed + `#[inline(never)]` parse; per-CPU Stream split into lazy
   per-direction `Option<Box<FrameCompressor/Decoder>>`.
3. **zstd DECODE 16 KiB→2 KiB** — heaped `FSETableImpl.decode` (`[MaybeUninit;512]`
   ×3 = 12.5 KiB) via `Box::new_uninit()` in vendored structured-zstd. Swap
   ACTIVATES.

Confirmed by `debug-stack-guard` (0xa5 canary, checked every ctx switch — never
booted before): fired at disksize → `runqueue.rs:103 Task kernel stack underflow`.

## NEW FRONTIER (Layer 2) — timer-deadline wakeups stop firing (~25s)
Boot reaches swap.target (~25s) then wedges: `[WATCHDOG] no-progress: 0 context
switches for 40s`. DIAGNOSIS (debug-taskdump+debug-wakelat): every task sleeps
on a PAST-DUE `wake_dl_ns` that never fired (at t=40s: deadlines 10.8/22.5/25.5/
29.1s, all past, still S). **`ktimers` (timer kthread tid 4096) itself sleeps
past-due (8.27s)** → nobody runs `run_due`, no deadline fires, cascade wedge.
The TICK still fires (`WLTICK n` 8192→12288→16384, ~10ms period) but with 163ms
`WLTICKGAP`s and **0 context switches** — i.e. the tick increments but drives NO
deadline-scan/wakeup/reschedule. One task has a GARBAGE deadline
(systemd-resolved wake_dl_ns=16661888537922279547 — corrupt/uninit). PRE-EXISTING,
separate from the stack overflow.
NEXT: trace the tick→deadline-wake path — why does the LAPIC tick not wake
ktimers / run `run_due` / trigger resched? Suspects: run_due kthread not
re-armed; the periodic-tick resched hook; one-shot deadline registration. Also
the garbage wake_dl (uninit timeout in poll/epoll deadline calc).

## First command next session (fresh main)
Boot: `mcp qemu_start arch=x86_64 features=debug-boot,debug-taskdump,debug-wakelat mem=2G accel=kvm paused=false` → qemu_continue → grep serial `WATCHDOG|TASKDUMP|WLLAT` → who's supposed to wake whom at ~22s.
Follow-ups: vendor `direct_eligible` buffered-forcing gate can be reverted now (FSE box makes direct fit); minor.
