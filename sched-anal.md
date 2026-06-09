# Scheduler / threading fix plan

Linux-shaped plan. Not rollback/recovery sequencing.

## Goal

Implement thread preemption and async signal delivery the way Linux is structured:

1. IRQ/timer path does accounting, wakeups, and sets resched state.
2. Actual scheduling happens through one scheduler path.
3. Return-to-user path is where the kernel decides:
   - schedule first if needed
   - deliver signal frame if needed
   - return to user
4. Go async preemption rides the signal-delivery path, not a second ad hoc switch path.

## Current problem

The current design drifted into two switch models:

1. normal `schedule()`
2. IRQ-tail staged context switching

That is the wrong shape. It creates:

1. two sources of truth for the current task/context
2. two frame contracts that must stay perfectly aligned
3. two ownership models for `prev`/`next`
4. intermittent corruption risk under timer preemption, fork first-run, and signal return

## Target architecture

### 1. One scheduler path

Use one task-switch primitive only:

- `schedule()`

Rules:

- all task switches use `schedule()`
- `rq.current` is the only source of truth
- runqueue membership changes happen only in the scheduler/wake/sleep paths
- no IRQ-tail direct task switch machinery

Implication:

- delete staged `prev_ctx/next_ctx` switching as the primary design
- timer/IPI code may request reschedule, but may not perform a distinct context-switch protocol

### 2. Linux-style reschedule flow

Timer / IRQ path:

1. charge runtime
2. wake expired timers / wake sleepers / set task flags
3. set `need_resched`
4. return into the normal kernel exit path

Kernel exit path:

1. if returning to kernel context, do not invent a second switch path
2. if returning to user and `need_resched` is set, call `schedule()`
3. after `schedule()` returns on the winning task, re-evaluate user return state
4. if a signal is deliverable, build the signal frame
5. return to user

This is the structure to copy from Linux: interrupt context requests reschedule; the normal scheduler path performs it at a safe exit point.

### 3. Linux-style signal delivery

Signal delivery belongs to return-to-user:

1. compute `pending & ~blocked`
2. choose next deliverable signal for the current thread
3. build arch signal frame on user stack / altstack
4. patch saved user return state to enter the handler
5. `rt_sigreturn` restores saved user state and mask exactly

This same path handles:

- normal user signals
- async thread-directed signals
- Go async preemption signal

### 4. Go async preemption

Go does not need a custom IRQ-tail scheduler. It needs:

1. a running user thread can be interrupted by timer IRQ
2. kernel can mark that exact thread for async signal delivery
3. on the next return to user for that thread, handler runs

Implementation shape:

1. timer tick identifies an overlong running user thread
2. mark thread-pending `SIGURG`
3. set resched state if scheduler wants someone else first
4. on eventual user return of that thread, inject the handler frame

Result:

- CPU-bound Go thread gets interrupted
- no syscall boundary required
- no second context-switch design required

## What NOT to do

### 1. Do not keep two switch engines

Do not keep both:

1. `schedule()`
2. IRQ-tail direct context switching

That guarantees split ownership of:

- current task
- current context
- saved frame contract
- wake/resched semantics

Pick one. The right answer is `schedule()`.

### 2. Do not let IRQ code become scheduler code

Do not put runqueue ownership, task swapping, or ad hoc `prev/next`
protocols into IRQ stubs or IRQ-tail glue.

IRQ code may:

1. save machine state
2. run dispatcher logic
3. set flags
4. return to common exit handling

IRQ code may not:

1. become a second task-switch path
2. own `rq.current`
3. own a separate notion of "current context"

### 3. Do not deliver signals from a side path

Do not build signal-frame delivery in one-off timer code, wakeup code, or
special Go-only glue. Signal delivery belongs to the return-to-user path.

If signal delivery is not on the common user-return path, it will drift out
of sync with:

- mask restore
- altstack handling
- syscall return semantics
- fork/exec signal state

### 4. Do not re-land futex/timerfd while scheduler core is moving

Do not mix:

- scheduler core rewrite
- signal-frame rewrite
- futex bitset work
- timerfd work

If boot/login breaks, mixed patches destroy bisection value.

### 5. Do not trust smoke alone

Do not treat `oxide login:` appearing as success.

Real acceptance is:

1. boot
2. login
3. shell prompt
4. fork/exec works
5. repeat multiple times

### 6. Do not debug with trace floods

Do not turn on broad scheduler/IRQ logging that changes timing enough to
hide or create races. Use:

1. ring buffers
2. one-shot traces
3. targeted event counters

Not serial floods.

### 7. Do not special-case x86 then "port later"

Do not accept a design that only makes sense on x86 IRQ tail details.

The model must be arch-neutral:

1. IRQ requests resched
2. common exit path consumes it
3. signal delivery happens on user return

Then each arch supplies the frame mechanics.

## How to avoid failure

### 1. Keep one owner per piece of truth

Explicitly assign ownership:

- `rq.current` owns "who is running"
- `schedule()` owns task-context changes
- return-to-user slow path owns resched-before-user-return
- signal delivery path owns signal-frame injection

If two places own the same truth, stop and redesign before coding.

### 2. Force identical logical flow on both arches

Before writing asm or arch glue, write the arch-neutral sequence first:

1. IRQ sets resched / pending work
2. kernel exit decides whether to schedule
3. winner task checked for signal delivery
4. user frame patched if needed
5. user return

Then implement x86 and arm against that exact sequence.

### 3. Prove frame contracts before boot-debugging

Before relying on QEMU:

1. pin frame offsets in unit tests
2. pin signal-frame alignment/restorer rules
3. pin first-run/fork-return stack images

Do not use boot debugging to discover basic layout mistakes that unit tests
can prove instantly.

### 4. Add one minimal repro per mechanism

Use one tight repro for each layer:

1. scheduler: runnable tasks rotate correctly
2. signal delivery: handler enters and returns correctly
3. Go preemption: spinning thread takes async signal

Do not jump straight to the full Go tools as the first proof.

### 5. Keep patches single-purpose

Each patch should answer one question only:

1. does resched-on-user-return work?
2. does signal-frame injection work?
3. does async thread-directed signal delivery work?

If a patch answers three questions at once, split it.

### 6. Fail fast on the known bad signs

Stop immediately if any change causes:

1. intermittent login failure
2. shell prompt missing after login
3. fork child corruption
4. handler return corruption
5. "works with logs, fails without logs"

That means the design or ownership boundary is still wrong.

## Concrete work

## 1. Remove IRQ-tail switching from the design

Do not "fix" the staged IRQ switch path. Replace it.

Tasks:

1. stop relying on `schedule_from_irq()` as a real switch engine
2. remove per-CPU staged prev/next context slots from the scheduling design
3. make IRQ stubs always return through the common kernel exit path
4. keep IRQ code responsible only for:
   - save frame
   - dispatch IRQ work
   - set flags
   - resume common exit handling

Acceptance:

- timer/IPI paths never directly switch tasks
- only `schedule()` changes kernel task context

## 2. Build one common return-to-user slow path per arch

Need explicit x86 and arm slow paths with the same semantics.

Order:

1. inspect current task / current saved user frame
2. if `need_resched` and preemption allowed, call `schedule()`
3. reload current task after scheduling
4. if signal deliverable, build signal frame
5. return to user

Requirements:

- x86 and arm must follow the same logical order
- this path owns signal injection
- this path owns reschedule-before-user-return

Acceptance:

- both arches have an explicit slow path, not scattered ad hoc checks

## 3. Make preempt bookkeeping match Linux shape

Fix bookkeeping so flags and safe points agree.

Tasks:

1. audit `preempt_disable`
2. audit `PreemptGuard`
3. audit `preempt_enable_no_check`
4. wire real decrement-to-zero behavior where intended
5. ensure IRQ code sets resched state, not performs hidden switching

Design rule:

- interrupt path may request preemption
- safe scheduler entry points perform it

Acceptance:

- no ambiguity about who consumes `need_resched`
- no guard API that implies behavior it does not provide

## 4. Rebuild signal frame delivery correctly

Use the Linux-shaped model, not a scheduler workaround.

Tasks:

1. rebuild/pin x86 `rt_sigframe` layout
2. rebuild/pin arm `rt_sigframe` layout
3. restore mask exactly on `rt_sigreturn`
4. validate altstack behavior
5. validate thread-directed signal targeting

Acceptance:

- handler entry/return correct on both arches
- blocked-mask behavior survives repeated cycles

## 5. Add Go-focused async-preemption proof

Need a direct proof before reintroducing the larger Go userspace stack.

Minimum repro:

1. one user thread spins in a tight loop
2. timer tick marks async-preempt signal pending
3. handler runs on that thread
4. thread survives return and continues correctly

Then:

1. validate on both arches
2. only after that, retry the actual Go tools

Acceptance:

- async signal interrupts a CPU-bound user thread on x86 and arm

## 6. Re-land futex/timerfd after the core is fixed

These are follow-ons, not the architectural center.

Order:

1. futex WAIT_BITSET / WAKE_BITSET
2. timerfd ABSTIME

Rule:

- do not mix these with scheduler-core rewrites

## What to test

## Hosted / unit

1. context/frame layout assertions
2. first-run task entry
3. fork child first return
4. resched-before-user-return logic
5. signal frame build/restore
6. no double-enqueue / no zombie rerun

## QEMU / system

1. x86 boot -> login -> shell repeated
2. arm boot -> login -> shell repeated
3. fork/exec stress
4. signal-delivery stress
5. user spin-loop async-preemption repro
6. Go-tool repro after minimal signal repro passes

## Implementation order

1. delete IRQ-tail switching as architecture
2. add common return-to-user slow path
3. fix preempt bookkeeping to feed that path
4. restore signal-frame delivery on that path
5. prove Go async preemption on a spin-loop test
6. re-land futex and timerfd changes on top

## Immediate next step

First patch should do this:

1. make timer/IPI IRQ handling stop being a task-switch engine
2. make it only set `need_resched`
3. start building the return-to-user slow path that consumes `need_resched`

That gets the design back onto Linux rails.
