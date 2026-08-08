# 32 Power + Reset

FROZEN 2026-05-02. Dep:`01`,`02`,`15`,`20`,`21`,`33`. Provides:`reboot` syscall, `init` shutdown.

## 1 Purpose

Halt, reboot, poweroff. Cpu idle. Frequency scaling stub.

## 2 Invariants (frozen)

1. `reboot()` syscall requires `CAP_SYS_BOOT`.
2. Shutdown sequence quiesces every CPU before invoking firmware reset path.
3. No AML interpreter yet (phase 35); power mgmt limited to halt + reset via UEFI Runtime Services or platform reset register.

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

C-states: not used yet (no AML). Phase 35 enables simple ACPI _CST table reading.

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
object and requires AML evaluation (`§2` invariant 3). The FADT's PM1a/PM1b
control blocks and the ACPI 5.0 sleep-control/sleep-status registers are parsed
and available; the AML evaluation is the only missing input.

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

`15` (reboot syscall), `20`/`21` (cpu halt instructions), `33` (UEFI/PSCI), `13` (kthread of init shutdown).
