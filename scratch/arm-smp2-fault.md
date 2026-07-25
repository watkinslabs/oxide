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

## Root cause — FOUND and FIXED (B1399)

Two defects, both now closed. Neither was "frames too fat", which is what the
`ABOVE-TOP`/`OWNER-MISMATCH` signature was misread as for several sessions.

**1. `schedule()` had no context guard at all.** No `might_sleep`, no
`in_atomic`. The softirq drain ran on the shared per-CPU IRQ stack, and a
handler could park from there — reached through the ALLOCATOR, not the device
code: handler allocates -> kalloc -> pmm -> `watermark::before_allocation` ->
`kswapd::direct_reclaim_once` -> pageout -> swap -> zram
-> `loading_waiters.park()` -> `schedule()`.

That is fatal because `oxide_arm_irq_dispatch` spills `x19` — the interrupted
frame base that the vector's `mov sp, x19` consumes — at the FIXED address
`irq_stack_top - 8`, which every outermost IRQ on that CPU rewrites. A task that
parked there resumed, reloaded a FOREIGN frame base, popped a foreign 288-byte
frame and `eret`ed with a foreign `SP_EL1`. Hence "SP just past some OTHER
task's kstack top, with `current()` naming a different task".

**2. Unbounded IRQ nesting during the softirq drain.** The drain re-enabled IRQs
(`msr daifclr, #2`) while running the deep block/net/fbcon tree. With the timer
period (10,000 ticks ~ 160 us) shorter than the drain, each level re-entered and
the frames accumulated: measured ~94 nested `oxide_irq_vector_handler` frames
(~348 B each) consuming a whole stack. Doubling `THREAD_SIZE` simply doubled the
count — the signature of a runaway, not of large frames.

### Fixes

| Fix | File |
|---|---|
| `preempt::in_atomic()` = `in_interrupt() \|\| on_irq_stack()` | `sched/src/preempt.rs` |
| `schedule()` refuses + reports `[BUG] scheduling while atomic` instead of switching | `sched/src/live/schedule/switch.rs` |
| Softirq drain stays on the IRQ stack (Linux `do_softirq_own_stack`; arm64 selects `HAVE_SOFTIRQ_ON_OWN_STACK`) and runs with IRQs MASKED, so it cannot nest | `arch-irq/src/gic/dispatch.rs` |
| Exception-entry SP guard: reset `SP_EL1` to `kstack_top` on EL0->EL1 (x86 TSS-RSP0 parity), bounds-check on EL1->EL1, report on a per-CPU overflow stack | `hal-aarch64/src/vbar/asm.rs`, `hal-aarch64/src/badstack.rs` |
| aarch64 publishes the current task's kstack top per-CPU (x86 already did via `set_rsp0`) | `sched/src/live/schedule/switch.rs`, `hal-aarch64/src/vbar.rs` |
| Boot asm left the assembler in `.section .bss`; with `lto = "fat"` the next crate's module-level asm landed in a NOBITS section | `boot-aarch64/src/selfboot/asm.rs` |

Result: `-smp 2` no longer corrupts memory and no longer overflows any stack —
zero `[FAULT]`, zero `[BADSTACK]`.

## Still open: `-smp 2` hangs in `execve`

No corruption, no overflow. CPU 1 sits in `execve` with nothing runnable on
either CPU — a lost wakeup, most likely a dropped/never-delivered block
completion. Distinct bug class from everything above; start from the sysrq
heartbeat dump (`CPU 1 last-tid=<pid> execve nr_run=0`).

Two leads recorded while measuring, both from independent analysis:

* **`preempt_count` is per-CPU and is NOT saved/restored across a context
  switch** (`sched/src/preempt.rs`), while Linux keeps it per-task in
  `thread_info`. Anything parking between `bh.rs`'s `SOFTIRQ_OFFSET` add and sub
  leaks the softirq field to the incoming task: that CPU then never drains
  softirqs again, `should_resched` is never true, and the eventual
  `preempt_count_sub` underflows. Stack-independent, and a plausible cause of
  exactly this hang.
* **Gating direct reclaim on `in_atomic()`** (Linux `GFP_ATOMIC` parity) is the
  correct shape and is written up in `mm-pmm/src/watermark.rs`, but applying it
  regressed x86 to this same hang, because the block-completion softirq
  allocates (`collect::<Vec<_>>()`) and does not cope with `Enomem`. Apply it
  together with making that handler allocation-free.

## Stack-frame de-bloat targets (measured with `-Zemit-stack-sizes`)

135 functions are >=1 KiB, 86 >=2 KiB, 62 >=4 KiB. Linux arm64 has essentially
none that big on a syscall path. Ranked:

1. zram/zstd: `compress_block_encoded_borrowed` 37,728 B, `new_encoder` 37,120 B,
   `estimate_subblock_size` 33,280 B — a 76 KiB chain that blows any THREAD_SIZE.
   Only reachable with `comp_algorithm=zstd`, which Fedora's zram-generator sets.
2. `core::slice::sort::stable::driftsort_main` 4,160 B x 25 instantiations
   (reserves `AlignedStorage<T,4096>` whenever `len > 20`). `sort_unstable_*` is
   0-416 B. Call sites include `netfilter::eval` on the softirq path.
3. `exec/src/stack.rs:104` `build_user_stack` — two `[0u64; 256]` arrays = 4,096 B,
   and it is the exact frame a demand fault nests on during `execve`.
4. `hal-aarch64/src/signal.rs:104` `build_signal_frame` 4,816 B — materializes the
   whole `RtSigframe` (incl. `__reserved: [u8; 4096]`) in the kernel frame.
5. `sched/src/xfer.rs` — four `[0u8; PAGE_SIZE]` buffers in sendfile/splice/
   vmsplice/copy_file_range.
6. `Task` (~3.3 KiB) built by value then moved into `Arc`; the fork path pays it
   twice (~9.7 KiB across `sys_clone_dispatch` -> `clone_spawn_arch` -> `spawn_*`).

## Historical frontier (superseded — kept so it is not re-derived)

The pre-B1399 frontier read "SP is 32 bytes above a kernel-stack top that belongs
to another task". That was defect 1 above: a foreign `x19` reloaded from
`irq_stack_top - 8`, not an arithmetic error in any entry path.
