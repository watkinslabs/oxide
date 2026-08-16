# 32a Suspend + Resume

FROZEN 2026-08-15. Dep:`01`,`02`,`06`,`13`,`15`,`20`,`21`,`23`,`32`,`33`,`35`,`54`. Provides:`/sys/power/*`, system sleep states.

## 1 Purpose

System sleep: the three suspend states, the ordered sequence that reaches them,
the task freezer, wakeup-event accounting, and the device/core callbacks that
let a machine come back. `32` owns the terminal transitions (halt, reset,
poweroff); everything reversible is here.

## 2 Invariants (frozen)

1. Three sleep states exist, named by the labels userspace writes to
   `/sys/power/state`: `freeze` (suspend-to-idle), `standby`, `mem`.
   `mem` is an indirection: it enters whichever mechanism `/sys/power/mem_sleep`
   currently selects.
2. `freeze` is always available and needs no platform support. `standby` and
   `mem` exist only when a platform operations table admits them (`§4`), so a
   machine whose firmware offers neither shows only `freeze`.
3. The sequence order in `§5` is the contract. Every step's undo runs in exactly
   reverse order, and a sequence that fails at step *k* unwinds steps *k-1..0*
   and no others.
4. A wakeup event that arrives at any point after the wakeup count is armed
   aborts the suspend instead of being lost. A suspend that completes while a
   wakeup was pending is a defect, not a race.
5. The task that requests the suspend is never frozen.
6. Interrupts are disabled across the platform enter, and the core callbacks
   (`§7`) run with them disabled and one CPU online.
7. Sleep states that lose CPU context (`standby`, `mem`) require a resume vector
   and a saved processor state; a platform that cannot supply both must not
   admit the state in `§4`'s validity check.

## 3 States

| Label | Internal | Mechanism | CPU context |
|---|---|---|---|
| `freeze` | `ToIdle` | frozen tasks + suspended devices + idle CPUs | retained |
| `standby` | `Standby` | platform's shallow state (ACPI S1) | retained |
| `mem` | `Mem` | platform's deep state (ACPI S3, PSCI `SYSTEM_SUSPEND`) | lost, restored from the resume vector |

`/sys/power/mem_sleep` names the same three by their mechanism labels —
`s2idle`, `shallow`, `deep` — and brackets the selected one:
`[s2idle] deep`. Writing one of the listed labels selects it; writing anything
else is `EINVAL`. Writing `mem` to `/sys/power/state` enters the selection.

## 4 Platform operations

Two tables, both optional, both registered once at boot:

| Table | Members | Applies to |
|---|---|---|
| suspend ops | `valid`, `begin`, `prepare`, `prepare_late`, `enter`, `wake`, `finish`, `suspend_again`, `end`, `recover` | `standby`, `mem` |
| s2idle ops | `begin`, `prepare`, `prepare_late`, `wake`, `restore_early`, `restore`, `end` | `freeze` |

A state is valid when suspend ops exist, `valid(state)` admits it, and `enter`
is present. `freeze` is valid unconditionally. The validity result is what
`/sys/power/state` reads: the available set, never a superset.

## 5 Sequence

Order is the contract (`§2.3`). Left column is the forward step; right is its
undo, run in reverse.

| # | Forward | Undo |
|---|---|---|
| 0 | filesystem sync (skipped when `sync_on_suspend` is 0) | — |
| 1 | freeze userspace tasks | thaw all tasks |
| 2 | freeze freezable kernel threads | thaw kernel threads |
| 3 | platform `begin` | platform `end` |
| 4 | suspend consoles | resume consoles |
| 5 | device `prepare`, registration order | device `complete`, reverse |
| 6 | device `suspend`, reverse registration order | device `resume`, registration order |
| 7 | platform `prepare` | platform `finish` |
| 8 | device `suspend_late`, reverse | device `resume_early`, forward |
| 9 | platform `prepare_late` | platform `restore` |
| 10 | device `suspend_noirq`, reverse | device `resume_noirq`, forward |
| 11 | platform `prepare_noirq` | platform `wake` / `restore_early` |
| 12 | offline secondary CPUs | online secondary CPUs |
| 13 | disable interrupts | enable interrupts |
| 14 | core `suspend`, reverse registration order | core `resume`, forward |
| 15 | platform `enter` | (returns on wakeup) |

`freeze` stops after step 11 and runs the s2idle loop (`§8`) in place of steps
12-15; it needs neither CPU offlining nor the platform enter.

Steps 1 and 2 fail by thawing everything already frozen and returning `EBUSY`.
Steps 5-11 fail by unwinding the undos of every step below them. Step 14 fails
by resuming only the core callbacks that had already suspended.

The wakeup check (`§6`) runs at step 1's retry loop, at step 14's entry, and
immediately before step 15; a pending wakeup at any of them turns the sequence
around at that point.

## 6 Wakeup accounting

One counter word holds two fields: registered events in the high half, events
in progress in the low half. A wakeup source activating increments in-progress;
deactivating moves it to registered atomically in one add.

| Call | Meaning |
|---|---|
| `pm_get_wakeup_count` | read the registered count; block until in-progress is zero |
| `pm_save_wakeup_count(n)` | arm the check if `n` equals the registered count and none are in progress; otherwise disarm and fail |
| `pm_wakeup_pending` | armed and (registered moved, or any in progress), or an unconditional abort was posted |
| `pm_system_wakeup` | post an unconditional abort and wake s2idle |
| `pm_wakeup_clear` | clear the abort and the recorded wakeup IRQs |

`/sys/power/wakeup_count` reads the count and writes it back; the read-then-write
pair is what closes the race between userspace deciding to suspend and an event
arriving. Reading returns `EINTR` when in-progress is nonzero and the wait was
interrupted; writing a stale count fails with `EINVAL` and prints the active
sources.

Each device carries `power/wakeup`, `enabled` or `disabled`, plus the
`wakeup_count`/`event_count`/`active_count` statistics of its source.

## 7 Core callbacks

Subsystems with no device to hang from (interrupt controllers, the timer, the
clocksource) register a core operations table: `suspend`, `resume`, `shutdown`.
Suspend walks the registrations in reverse order with interrupts disabled and
one CPU online; a failing entry resumes only the entries already suspended.

## 8 Suspend-to-idle

`freeze` loops: check for a pending wakeup (or ask the s2idle ops' `wake`), and
if none, mark the s2idle state entered, push every CPU into its idle
instruction, and block until an interrupt sets the state to woken. The loop
exits when the wakeup check reports one. No firmware involvement, so this is the
state a virtual machine supports.

The s2idle state is three-valued — none, entered, woken — and the transition to
entered is taken under the same lock as the pending-wakeup check, so a wakeup
that lands between the two cannot be dropped.

## 9 Platform paths

**x86_64 / ACPI.** `_S1` and `_S3` are AML packages holding the PM1a and PM1b
`SLP_TYP` values, read the same way `32§5` reads `_S5`. Entry clears the wake
status bit, writes `SLP_TYP` to the PM1 control registers, then writes
`SLP_TYP | SLP_EN` as a second write. `mem` additionally publishes a physical
resume address in the firmware waking vector of the FACS and saves the
processor state the firmware does not preserve — control registers, the segment
and descriptor-table registers, the syscall MSRs, and the callee-saved general
registers. Firmware resumes in real mode at the waking vector; the resume
trampoline re-enters long mode with the kernel page tables and jumps to the
saved instruction pointer.

**aarch64 / PSCI.** `mem` is `SYSTEM_SUSPEND`, admitted only when `PSCI_FEATURES`
reports it. The call takes the physical resume entry point and a context
identifier; the caller saves the EL1 system-register state (translation-table
base and control, memory attributes, system control, vector base, per-CPU base,
debug control) and the callee-saved general registers, because the call returns
directly to the resume entry with none of it live. `standby` is not offered:
PSCI has no shallow system state.

A platform that reports `SYSTEM_SUSPEND` unsupported offers `freeze` alone,
which is the correct reading of the firmware, not a gap.

## 10 Freezer

A frozen task is one that has observed the freeze flag at a signal-delivery or
syscall-exit point and parked itself. Kernel threads observe it at their own
freeze checkpoints; a thread that must keep running across a suspend is marked
no-freeze and is never counted.

The freeze pass counts tasks that still need to freeze, retries with a backoff
starting at one millisecond and doubling to eight, and gives up after twenty
seconds. On give-up it names every task that refused, thaws everything, and
returns `EBUSY`. A wakeup arriving during the pass aborts it the same way.

Userspace freezes first and kernel threads second, so a kernel thread servicing
a frozen userspace task still runs while that task parks.

## 11 sysfs surface

| Path | Mode | Content |
|---|---|---|
| `state` | rw | available labels, space-separated; write enters one |
| `mem_sleep` | rw | mechanism labels with the selection bracketed |
| `wakeup_count` | rw | registered wakeup events; `§6` |
| `pm_async` | rw | `0`/`1`, asynchronous device phases |
| `pm_debug_messages` | rw | `0`/`1`, sleep-transition debug logging |
| `sync_on_suspend` | rw | `0`/`1`, step 0 of `§5` |
| `suspend_stats/` | ro | success, fail, per-step failure counts, last failed device, errno and step |

Writes accept an optional trailing newline. A write that names no known label is
`EINVAL`; a write while a transition is already running is `EBUSY`.

Statistics step names are the `§5` step group that failed: `freeze`, `prepare`,
`suspend`, `suspend_late`, `suspend_noirq`, `resume_noirq`, `resume_early`,
`resume`.

## 12 Test contract (frozen)

- State validity: with no platform ops only `freeze` is listed; ops admitting
  `mem` alone list `freeze mem`; `standby` appears only when admitted.
- `mem_sleep` selection: the bracket moves to the written label; an unlisted
  label is `EINVAL` and leaves the selection unchanged; `mem` on `state` enters
  the selected mechanism, not `Mem` literally.
- Sequence order: the forward step list is exactly `§5`, and the undo list for a
  failure at every single step *k* is the reverse of steps `0..k`, checked for
  all *k*.
- Freezer: the count reaches zero and the pass succeeds; a task that never
  freezes exhausts the timeout, is named, and everything thaws; a wakeup during
  the pass aborts it and thaws.
- Wakeup race: arming with a stale count fails; arming with the current count
  succeeds; an event registered after arming makes the pending check true
  exactly once and disarms; an in-progress event makes it true without any
  registered movement.
- s2idle: a wakeup posted between the pending check and the state store does not
  produce an entered-and-never-woken state.
- Core callbacks: a failure at entry *k* of the reverse walk resumes exactly the
  entries already suspended, in forward order.
- sysfs formatting: every attribute's rendering byte-for-byte, including the
  trailing newline and the bracket placement.
- Coverage ≥85%.

## 13 Failure modes

- Freeze timeout: `EBUSY`, everything thawed, the refusing tasks named.
- Device suspend failure: the failing device is recorded, the sequence unwinds,
  the statistics step counter increments.
- Platform enter returning: treated as a wakeup; the sequence unwinds normally.
- Wakeup during the noirq phase: aborts before the platform enter, so the
  machine never enters a state it cannot be woken from.
- No platform ops at all: `mem` and `standby` are absent from `state`, and a
  write naming them is `EINVAL`.

## 14 Debug

`debug-suspend`: log every step of `§5` with its result, the freezer's per-round
count, and every wakeup-count arm/disarm.

## 15 Cross-spec

`32` (terminal transitions, idle instruction), `13` (task registry, kthreads),
`23` (timer/clocksource core callbacks), `33` (FADT, FACS, AML, PSCI),
`35` (device driver callbacks), `54` (CPU state save/restore asm rules).
