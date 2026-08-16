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

C-states: not used yet. Phase 35 enables simple ACPI `_CST` table reading.

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

Now: nothing. CPU runs at firmware-set frequency.
Later phase: simple cpufreq stub via MSR (x86) / SCMI (arm); userspace `cpufreq` daemon manages governors.

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
