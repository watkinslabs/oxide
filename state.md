# state.md — session hand-off

Branch: `main` @ `236af1107` (PR #3922 merged). Clean tree, no open PRs.

## Headline

**x86 green. arm green at the gate (`smp=1`). arm `smp=2` still aborts at ~11 s —
but it is now precisely characterised rather than guessed at.**

The instrument that did it landed as #3922: Linux `show_regs()` parity in the
aarch64 oops dump. Five previous sessions ran one hypothesis per boot; the dump
answered the question in a handful of boots and disproved the leading theory.

## Done this session

- **#3901** aarch64 fault-vector ELR/SPSR/SP_EL0 round-trip (Linux `kernel_entry`
  parity). This is what made ARM boot systemd at all.
- **#3913** park-loop GIC quiesce — `WFI` is not DAIF-gated, so a masked-pending
  IRQ turned the fatal-fault park into a 100 %-CPU spin — plus smoke fail-fast on
  `[FAULT]` instead of waiting out the full timeout.
- **#3917** arch gate honest at `smp=1` + Linux hardirq accounting (`irq_enter`/
  `irq_exit`, the missing third `preempt_count` field).
- **#3918** RCU `set_cpu_hooks` was never called anywhere — grace periods
  completed on CPU 0 alone on every SMP boot to date. Premature-GP UAF, fixed.
- **#3922** `showregs`: full GPR set + CPU id + SPSR decode + IRQ-stack window
  position + free-IP provenance over every register, not three hand-picked ones.

Gate: arm `smp=1` → `basic.target` in 114 s, 0 faults. `cargo test -p sched`
187/0. Both kernel targets build.

## Open: ARM `-smp 2` aborts at ~11 s

Full evidence ledger + reproduction recipe: **`scratch/arm-smp2-fault.md`**.
Read it first — it lists everything already disproved, with the disproof.

Signature, stable across every boot measured:

- `SP_EL1 == <some task>::kstack_top + 32`, so the vector's 288-byte frame push
  straddles the stack top: the first stores land in the **neighbouring slot** and
  the store that crosses faults on its guard page. For the two per-CPU IRQ
  stacks — adjacent slots in one window — that neighbour is **another CPU's live
  IRQ stack**. That is the silent cross-CPU corruption.
- always `mpidr=1` (the AP), `preempt_count=0` (`hardirq=0 softirq=0` — plain
  task context), and `OWNER-MISMATCH`: the SP is on a stack owned by a
  **different tid than `current()`** (tid 4106 on tid 4105's stack, and those two
  are *siblings*, both `ptid=4104`).
- `lr` = `oxide_irq_vector_handler+0x88…0x90` — the IRQ epilogue's `mov sp, x19`
  or the instruction after it.

Disproved this session (do not re-check; details in the ledger): kernel-stack
exhaustion (`headroom=32512` of 32768 — nearly empty, and raising `THREAD_SIZE`
16→32 KiB changed nothing), nested-IRQ pile-up, softirq-drain parking on the
shared per-CPU IRQ stack, deferring the drain to `ksoftirqd` (**deadlocks** —
voluntary-preempt kernel plus busy-poll block wait, measured as a wedge in
`execve` with `ksoftirqd R y cpu1 cputime=0`), any frame-size/pop asymmetry in
the entry asm (every `sub sp`/`add sp` is 288 or a balanced 16-byte preamble on
mutually exclusive branches), RCU, task migration, the AP GIC/IRQ/softirq path,
ARM TLB maintenance, raw-`aff0`-as-cpu-id.

No asm path adjusts SP by 32, so the value arrives via a `mov sp, <reg>`:
`mov sp, x19` (this IRQ's frame base), `mov sp, x9` (the incoming task's
`Context.sp`), or `mov sp, x10` (per-CPU `irq_stack_top`).

## First task next session

Catch the **first** entry with a bad SP instead of its consequence — port Linux
arm64's `kernel_ventry` SP-bounds check → `__bad_stack` / `handle_bad_stack`,
which diverts to a per-CPU overflow stack and reports with the previous frame
still intact. Two prerequisites, both genuine lockstep gaps found while measuring:

1. **aarch64 never publishes the current task's kstack top per-CPU.** x86 does it
   on every switch (`live/schedule/switch.rs` ~line 330: `set_rsp0` +
   `set_syscall_kstack`); the aarch64 block beside it publishes only
   `set_current_svc_frame`. Add a per-CPU slot — `vbar.rs` uses 0 = cpu id,
   24 = svc frame, 32 = irq stack top, so 40 is free — and publish it in that
   same block. The entry check has nothing to compare against without it.
2. **kstacks are not `THREAD_SIZE`-aligned**, so Linux's 4-instruction
   `tbnz x0, #THREAD_SHIFT` trick does not apply: slots are `guard(1 page) +
   stack(4 pages)` = `0x5000` stride, so `stack_lo = base + n*0x5000 + 0x1000`.
   Moving to a `0x8000` stride with the 16 KiB stack at the aligned base and a
   16 KiB unmapped guard above buys both Linux's exact check and a far wider
   guard. VA is free; only the mapped 4 pages cost frames.

Literal first command:

```
sed -n '320,345p' crates/kernel/sched/src/live/schedule/switch.rs
```

Unrelated, found while reading, worth closing: `ContextAArch64::new_user`
(`crates/arch/hal-aarch64/src/context.rs`) builds `sp = stack_top, lr = 0` — a
switch into that context would `ret` to address 0. Confirm unreachable or delete.

## Harness gotcha that cost time

`tools/boot-smoke.sh` **deletes a failed attempt's log** (`rm -f "$LOG"`), so any
post-mortem the kernel printed is gone. Always pass `SMOKE_KEEP_LOG_DIR=<dir>`
when investigating. Also: the Bash tool caps at 10 min, shorter than an arm boot
budget — run boots with `run_in_background` and `SMOKE_TIMEOUT`.
