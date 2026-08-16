# 32 Power + Reset

FROZEN 2026-08-15. Dep:`01`,`02`,`15`,`20`,`21`,`33`. Provides:`reboot` syscall, `init` shutdown.

## 1 Purpose

Halt, reboot, poweroff. Cpu idle. Frequency scaling stub. Reversible sleep states are `32a`.

## 2 Invariants (frozen)

1. `reboot()` syscall requires `CAP_SYS_BOOT`.
2. Shutdown sequence quiesces every CPU before invoking firmware reset path.
3. Power management acts through the firmware namespace where one exists (`33`): the terminal S5 action, and the ACPI power supplies of `32§13`. Platforms describing no AML fall back to halt + reset via UEFI Runtime Services or the platform reset register.
4. Terminal transitions are irreversible by construction: nothing after the firmware write may assume the machine still executes. Reversible transitions belong to `32a`.

## 3 Public ifc

```rust
sys_reboot(magic1:i32, magic2:i32, cmd:u32, arg:UVA<u8>) -> KR<i32>;
// magic1 = 0xfee1dead, magic2 = 0x28121969 (Linux compat)
// cmd: LINUX_REBOOT_CMD_RESTART, _POWER_OFF, _HALT, _RESTART2 (with arg=string)
```

```rust
pub fn cpu_idle();              // halt this CPU until next IRQ
pub fn cpu_poweroff_secondary();// shut down secondary CPUs at shutdown
```

## 4 Idle

`cpu_idle`:
- x86: `sti; hlt; cli` if interrupts pending (loop until IRQ wakes us).
- arm: `wfi`.

Idle-state selection is `32§14`; the scheduler's idle loop enters through it
and halts directly only where no driver is registered.

## 5 Reset / poweroff

x86_64 reset is a ladder, not one mechanism: each rung is a write the platform
may decline, and the next rung runs because the machine is still executing.

| Rung | Mechanism | Condition |
|---|---|---|
| 1 | FADT reset register (port, memory or bus-0 PCI config) | FADT revision ≥ 2 and the reset-register flag bit set; rung omitted otherwise |
| 2 | Keyboard-controller reset pulse (`0x64` ← `0xfe`, 10 attempts) | always |
| 3 | Chipset reset-control port (`0xcf9`, request then code) | always |
| 4 | Triple fault (zero-limit IDT + `int3`) | always; terminal, cannot be declined |

The reset register's declared bit width and offset are not consulted — firmware
fills them wrongly often enough that honouring them refuses resets the hardware
performs. Rung order and port encodings live in an ungated module and are
host-tested; only the writes themselves are arch-gated.

The reference also has UEFI Runtime Services and real-mode BIOS rungs. Neither
exists here: this kernel exits boot services on both arches and retains no
runtime-services pointer, and `36§2` forbids returning to real mode.

x86_64 poweroff needs the S5 `SLP_TYP` value, which lives in the DSDT `_S5`
object and is read by AML evaluation. The FADT's PM1a/PM1b control blocks and
the ACPI 5.0 sleep-control/sleep-status registers supply the registers written.
The sleep states share this decode path (`32a§9`).

aarch64:
- PSCI `SYSTEM_RESET` / `SYSTEM_OFF` — the platform's single authoritative
  mechanism, so no ladder.

## 6 Halt

After all userspace dies (init exit triggers panic; or `reboot(_HALT)`):
- Send `IPI_HALT` to all secondaries.
- Final CPU spins in `wfi`/`hlt` loop forever.

## 7 Frequency scaling

Frequency scaling is `32§15`.

## 8 Concurrency

Shutdown is single-threaded by design; one CPU coordinates, others halt on IPI.

## 9 Test contract (frozen)

- `reboot(POWER_OFF)` from userspace: QEMU exits with code 0.
- `reboot(RESTART)` from userspace: QEMU restarts (test via `-no-reboot` not set).
- FADT decode: every field reads from its own offset, and the declared offsets
  reproduce all five conformant table lengths.
- Reset-register admission: revision below 2, the flag bit clear, an address
  space outside port/memory/bus-0-PCI, a zero address, or a PCI device or
  function outside the bus's range each yield no reset register; an implausible
  declared bit width does not.
- Reset ladder: the triple fault is last and appears exactly once, the firmware
  rung is present only when a register exists, and no rung repeats.
- Idle test: leave system idle for 60s; CPU usage of idle task = ~100% (per stat).
- Coverage ≥80% (small subsystem).

## 10 Failure modes

- No FADT reset register: rung 1 is omitted, not attempted as a no-op — a rung
  that cannot act must not consume the settle delay that follows it.
- Every rung declined: the triple fault terminates the ladder unconditionally.
- PSCI not present (raw arm without firmware): kassert (we require PSCI per `03§7`).

## 11 Debug

`debug-power`: log every reboot attempt, idle state.

## 12 Cross-spec

`15` (reboot syscall), `20`/`21` (cpu halt instructions), `33` (UEFI/PSCI), `13` (kthread of init shutdown), `32a` (suspend/resume).

## 13 Power-supply class

Battery and adapter reporting. A desktop power daemon reads this tree and
nothing else; an absent or wrongly-scaled attribute is a wrong battery
indicator, not a missing feature.

Ownership: `crates/kernel/power-supply` owns the class (registered supplies,
the property contract, attribute visibility, the change path).
`crates/kernel/sysfs` projects it. Providers register into it; they never
publish a second registry (`52§5`).

### 13.1 Units (frozen)

| Property family | Unit |
|---|---|
| `voltage_*` | microvolts |
| `current_*`, `precharge_current`, `charge_term_current` | microamps |
| `power_*` | microwatts |
| `charge_*` | microamp-hours |
| `energy_*` | microwatt-hours |
| `time_to_*` | seconds |
| `temp*` | tenths of a degree Celsius |
| `capacity`, `capacity_alert_*`, `capacity_error_margin`, `charge_control_*_threshold` | percent |

### 13.2 Invariants (frozen)

1. A supply publishes exactly the attributes it declares. An undeclared
   property has no file — not an unreadable one. `type` is the sole exception:
   it is fixed at registration and always published read-only.
2. A writable property adds the owner-write bit; nothing else is writable.
3. Property read errors are distinct: `EINVAL` = the supply does not have this
   property, `ENODEV` = the value is not reported, `EAGAIN` = registration has
   not finished, `ENODEV` after teardown began.
4. Enum labels render with spaces replaced by underscores, so a uevent
   variable stays one token.
5. `uevent` names the supply first (`POWER_SUPPLY_NAME=`), then the category,
   then each declared property as `POWER_SUPPLY_<ATTR>=`. A property whose
   value is unavailable is skipped, never emitted empty.
6. A change fans out to every supply that draws from the changed one before
   the event reaches userspace.
7. Registration refuses a duplicate name (`EEXIST`) and a supply with no
   declared properties (`EINVAL`).

### 13.3 ACPI provider

`crates/kernel/firmware` publishes the firmware-described supplies: the
control-method battery (`PNP0C0A`, `_STA`/`_BIX`/`_BIF`/`_BST`/`_BTP`) and the
AC adapter (`ACPI0003`, `_PSR`). Firmware reports milli-units; the provider
converts at read time. Which capacity family a battery publishes follows the
unit firmware reports in, and a battery with no usable full-charge reference
publishes neither the percentage nor the level, in place of computing one.
Supply names come from the firmware object name, never from a kernel counter.

### 13.4 Test contract (frozen)

- Unit scaling, attribute visibility, the status ladder, the percentage
  arithmetic, the capacity level ladder and the uevent environment are hosted
  tests over ungated modules.
- A `_BIF` and a `_BIX` package decode to the same fields from their differing
  offsets; a short package is refused.
- An absent battery answers `present` and reports `ENODEV` for every other
  property.

## 14 CPU idle

Which state an idle CPU is put into, and the accounting that says whether the
choice was good. A CPU that never sleeps deeply costs power a laptop does not
have; one that sleeps too deeply pays a wakeup cost on every request.

Ownership: `crates/kernel/cpuidle` owns the state table, the governors, the
per-CPU counters and the attribute contract. `crates/kernel/sched` enters one
cycle per park from its idle loop. `crates/kernel/procfs` projects the tree.
Providers register the state table; they never publish a second one (`52§5`).

### 14.1 Units (frozen)

| Field | Unit |
|---|---|
| `exit_latency_ns`, `target_residency_ns` | nanoseconds |
| `latency`, `residency`, `time` attributes | microseconds |
| `power` attribute | microwatts |

Every decision is made on the nanosecond fields. The attributes report
microseconds because that is what firmware, device trees and every reader
speak; the conversion truncates.

### 14.2 Invariants (frozen)

1. One driver at a time. A platform provider that finds a real state ladder
   withdraws the registered one before publishing its own; two tables would
   leave two meanings for one state index, and every counter, attribute and
   governor decision is keyed by that index.
2. The state table is a ladder: target residency and exit latency both
   non-decreasing with index, and a polling state only at index zero. A table
   that is not is refused, not sorted.
3. The two reasons a state is unavailable are recorded separately. A state the
   driver declared unusable cannot be re-enabled by a write to `disable`.
4. `above` counts a sleep shorter than the entered state's own target
   residency, and only where a shallower state was enabled. `below` counts a
   sleep whose length net of the entered state's exit latency would have
   covered the next enabled deeper state's target residency.
5. A refused entry counts against the state that was asked for, not against
   whatever ran instead, and contributes no residency.
6. A machine whose platform describes no ladder still gets one state: the
   architecture halt. The accounting is the point, not the depth.
7. The sleep-length estimate is bounded by the tick period. This kernel does
   not suppress the tick, so a state whose residency exceeds it cannot pay for
   itself, and a governor told otherwise would keep choosing one.

### 14.3 Governors

`menu` predicts a duration — the time to the next timer scaled by a
correction factor learned per duration bucket, or a repeating interval
detected in the recent history, whichever is shorter — and takes the deepest
state that pays for it. `teo` predicts nothing and counts instead: per state,
how often a sleep ran to the timer against how often something else cut it
short, pulling the choice shallower as the interceptions outweigh the hits.
`teo` is the default.

### 14.4 Test contract (frozen)

- Unit reconciliation, table validation, the two mispredict classifications,
  both governors' selection and learning, the whole idle cycle against a
  hand-moved clock, and every attribute's rendering are hosted tests over
  ungated modules.
- A microsecond declaration read as a nanosecond one, and a nanosecond
  accumulator reported unconverted, each fail a named test.

## 15 CPU frequency scaling

The operating points a platform declares, every limit in force on them, and
the governor that chooses between them.

Ownership: `crates/kernel/cpufreq` owns the frequency table, the policy with
its limit aggregation, the governors, the transition statistics and the
attribute contract. `crates/kernel/sched` feeds the demand signal.
`crates/kernel/procfs` projects the tree. Providers register the driver and
the policies; they never publish a second registry (`52§5`).

### 15.1 Units (frozen)

| Field | Unit |
|---|---|
| every frequency | kilohertz |
| `cpuinfo_transition_latency` | nanoseconds |
| `time_in_state` | hundredths of a second |

Firmware reports megahertz and device trees report hertz. Both convert at the
provider boundary.

### 15.2 Invariants (frozen)

1. One driver, and one policy per clock domain. A CPU in two policies would
   have two answers to what it may run at.
2. Every limit source holds its own request and the effective pair is the
   tightest of them. A write to `scaling_max_freq` cannot release a thermal
   cap, and a cap lifting restores whatever the other sources still ask.
3. The ceiling is resolved before the floor and the floor is held at or below
   it. Inverted limits resolve toward the ceiling: exceeding a thermal or
   platform cap damages hardware, running slower than asked does not.
4. A resolution is clamped into the limits in force before the relation is
   applied, so no relation can step outside them. A minimum constraint
   resolves upward, a maximum downward.
5. The efficiency preference is soft. Where honouring it leaves nothing inside
   the limits, the resolution runs again without it.
6. A boost point is reachable only while boost is enabled, and does not raise
   the declared ceiling until it is.
7. A limit change re-targets immediately. A cap that waits for the next
   sampling window is a cap that is not in force.
8. The frequency table is checked for duplicates at registration: two indexes
   for one operating point make a resolution ambiguous.

### 15.3 Governors

`performance` and `powersave` sit at the ceiling and the floor. `userspace`
follows what was written to `scaling_setspeed`, re-clamped on every pass.
`ondemand` samples the busy fraction, jumps to the ceiling past a threshold
and interpolates across the hardware range below it. `schedutil` scales from
the scheduler's utilisation signal with a quarter of headroom, so an
eighty-percent-busy CPU asks for its full ceiling, and applies a
wait-for-IO boost that doubles on each consecutive such wakeup and halves on
every pass without one. `schedutil` is the default.

### 15.4 Test contract (frozen)

- The resolution rule under every relation, the limit aggregation across
  sources, each governor's decision, the boost state machine, the statistics
  and every attribute's rendering are hosted tests over ungated modules.
- A megahertz figure taken as kilohertz, and a nanosecond occupancy reported
  unconverted, each fail a named test.

## 16 Thermal

Thermal zones, cooling devices, and the binding between them, per `35§13`.
The critical trip's terminal action is this subsystem's: the machine powers
off rather than continuing to run past the temperature at which its hardware
is damaged.
