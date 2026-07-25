# ARM `-smp 2` boot fault — evidence ledger

Status per row. Branch column names the lane that produced the row.

`OXIDE_SMP=1` boots to `basic.target` and is the arch gate (`tools/boot-smoke.sh`
defaults arm to 1). `OXIDE_SMP=2` aborts at ~11 s guest time, every attempt.

## Reproduce + read the post-mortem

```
D=/tmp/armlogs; mkdir -p $D
FEATURES=debug-armctx OXIDE_SMP=2 OXIDE_SMOKE_ATTEMPTS=1 \
  SMOKE_KEEP_LOG_DIR=$D SMOKE_TIMEOUT=300 tools/boot-smoke.sh arm
grep -a -E '\[FAULT\]|\[REGS\]|\[ARMCTX\]' $D/arm-attempt-1-fault.log
```

`SMOKE_KEEP_LOG_DIR` is mandatory — `boot-smoke.sh` deletes a failed attempt's
log (`rm -f "$LOG"` after each attempt), so without it the dump is gone.

## The signature (stable across every boot measured)

| Field | Value | Meaning |
|---|---|---|
| `esr` | `0x96000047`, `dfsc=translation-l3`, `W` | write to an unmapped page |
| `far` | a kstack **slot guard page**, page-aligned | frame straddled a stack top |
| `elr` | `oxide_default_vector_handler+0x18…0x54` | fault is the vector's OWN frame push |
| `lr` | `oxide_irq_vector_handler+0x88…0x90` | interrupted code was the IRQ epilogue |
| `mpidr` | **1** | always the AP, never the BSP |
| `preempt_count` | **0** (`hardirq=0 softirq=0`) | plain task context |
| `headroom` | **32512 of 32768** | the stack is nearly EMPTY |
| `describe_va` | **OWNER-MISMATCH** | SP is on a stack owned by a DIFFERENT tid than `current()` |

Reconstructed: `SP_EL1 == <some task>::kstack_top + 32` (with 16 KiB stacks it was
`+ 64`). The vector's `sub sp,#288` then puts the frame base back inside the
mapped page, the first stores land in the **neighbouring slot**, and the store
that crosses the top faults on the guard page. For the two per-CPU IRQ stacks —
adjacent slots in the same window — the low half of that frame lands in the
**other CPU's live IRQ stack**, which is the silent cross-CPU corruption.

Concrete instance: `current()` = tid 4106 (`kstack_top=…90000`, slot 15) while
`SP` was on slot 14, `owner_tid=4105`, `LIVE`. 4105 and 4106 are **siblings**
(both `ptid=4104`), not parent/child.

## Ruled out — do not re-check

| Hypothesis | Disproof | Branch |
|---|---|---|
| Kernel-stack exhaustion / fat frames | `headroom=32512` of 32768 — stack nearly empty. Raising `THREAD_SIZE` 16→32 KiB did **not** change the fault; the task consumed the same ~256 B margin either way. | C215 |
| Nested-IRQ pile-up on the stack | `hardirq=0 softirq=0` at the fault | C215 |
| Softirq drain parking on the shared per-CPU IRQ stack | Moving the drain off it (Linux `irq_stack_exit` before `invoke_softirq`) changed the collateral but the fault persisted at ~11 s | C215 |
| Deferring the drain to `ksoftirqd` | **Deadlocks.** Kernel is voluntary-preempt (`oxide_irq_resched_on_exit` switches only on EL0 return) and the block wait busy-polls, so a task blocked in the kernel holds its CPU and the ksoftirqd that must complete its I/O never runs. Measured: wedge in `execve`, `ksoftirqd R y cpu1 cputime=0`. | C215 |
| A frame-size / pop asymmetry in the entry asm | Every `sub sp`/`add sp` in `hal-aarch64` is 288, or a balanced 16-byte preamble on mutually exclusive branches. No 32-byte path exists. | C215 |
| RCU premature grace period | reproduces with `sync::set_cpu_hooks` wired (#3918) | D381 |
| Task migration between CPUs | reproduces with tasks pinned to `task.cpu` | D381 |
| AP GIC / IRQ / softirq path | AP online + ticking with **no runqueue** boots clean, 118 s | D381 |
| ARM TLB maintenance | single-page invalidation is `tlbi vae1is` (inner-shareable); the `tlbi vmalle1` full-flushes are legitimately CPU-local | D381 |
| Raw `MPIDR_EL1.aff0` as the CPU id | QEMU `virt` builds affinity as `(idx/16)<<8 \| idx%16`, so `-smp 2` yields aff0 0,1 — dense. Real latent bug at ≥17 CPUs (Linux uses a dense `cpu_logical_map[]`); not this one. | C215 |

## Frontier

`SP_EL1` is 32 bytes above a kernel-stack top that belongs to another task, in
the IRQ epilogue, on the AP, in plain task context. No asm path adjusts SP by 32,
so the value arrives via a `mov sp, <reg>`:

* `mov sp, x19` — `oxide_irq_vector_handler+0x88`, x19 = this IRQ's frame base
* `mov sp, x9`  — `oxide_context_switch`, x9 = the incoming task's `Context.sp`
* `mov sp, x10` — the IRQ-stack switch, x10 = per-CPU `irq_stack_top`

Next step: catch the FIRST entry with a bad SP rather than its consequence — port
Linux arm64's `kernel_ventry` SP-bounds check (`__bad_stack` / `handle_bad_stack`),
which tests the entry SP against the current stack and diverts to a per-CPU
overflow stack. That reports the offending entry with the previous frame still
intact, instead of a frame that has already scribbled a neighbour.

Note `new_user` (`context.rs`) builds `sp = stack_top, lr = 0` — a switch to that
context would `ret` to address 0. Confirm it is unreachable or delete it.
