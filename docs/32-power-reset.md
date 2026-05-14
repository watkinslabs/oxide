# 32 Power + Reset

FROZEN 2026-05-02. Dep:`01`,`02`,`15`,`20`,`21`,`33`. Provides:`reboot` syscall, `init` shutdown.

## Revision 2026-05-09 (R01)

- Changed: `crates/power` is now the real owner of the
  reboot/halt/power-off primitives. `power::cmd(c)` dispatches
  Linux reboot(2) commands; `power::halt()` is the canonical
  CPU-park; `power::restart()` triple-faults (x86) or PSCI
  SYSTEM_RESET (arm); `power::power_off()` writes QEMU
  isa-debug-exit (x86) or PSCI SYSTEM_OFF (arm).
- Wiring: `kernel_sys_reboot` validates magic1/magic2 + CAP_SYS_BOOT
  then dispatches through `power::cmd`. `halt_forever` in
  `kernel/src/lib.rs` now delegates to `power::halt`.
- ACPI _S5 walk + PCI cf9 + 8042 reset port land with phase 35 (ACPI runtime + AML interpreter).

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

x86_64:
- Try UEFI Runtime Services `ResetSystem`.
- Else: triple-fault to force reset (kbd controller 0x64 0xfe deprecated; not used).

aarch64:
- PSCI `SYSTEM_RESET` / `SYSTEM_OFF`.

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
- Idle test: leave system idle for 60s; CPU usage of idle task = ~100% (per stat).
- Coverage ≥80% (small subsystem).

## 10 Failure modes

- UEFI Runtime Services unavailable: fall back to triple-fault; log warn.
- PSCI not present (raw arm without firmware): kassert (we require PSCI per `03§7`).

## 11 Debug

`debug-power`: log every reboot attempt, idle state.

## 12 Cross-spec

`15` (reboot syscall), `20`/`21` (cpu halt instructions), `33` (UEFI/PSCI), `13` (kthread of init shutdown).

