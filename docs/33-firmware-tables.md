# 33 Firmware Tables (ACPI + DT)

DRAFT 2026-05-02. Dep:`01`,`02`,`19`,`20`,`21`,`34`. Provides:PMM (mem map), `13` (CPU topology), `34` (PCI host bridges, MSI), IrqOps (controller), Time (frequency).
## 1 Purpose

Parse static ACPI tables (x86, optionally arm) and DT (arm primary; x86 fallback never). Expose results to subsystems.

## 2 Invariants (frozen)

1. Parsed once at boot; results cached as static tables.
2. No AML interpreter; only static tables: MADT, FADT, MCFG, SRAT, SLIT, HMAT, PPTT, HPET (sanity), DSDT skipped.
3. DT (FDT/DTB): walked once, converted to in-memory tree; published via `/sys/firmware/devicetree/base/`.
4. Memory map authoritative source: UEFI memory map + ACPI E820 (x86) or DT `/memory` node (arm).

## 3 Public ifc

```rust
pub struct CpuTopology { pub cores:Vec<CpuInfo>, pub packages:Vec<PkgInfo>, pub numa:Vec<NumaNode> }
pub fn cpu_topology() -> &'static CpuTopology;
pub fn pci_host_bridges() -> &'static [PciHostBridge];
pub fn irq_controller() -> IrqController;     // Apic | GicV3
pub fn timer_freq() -> u32;
pub fn rsdp() -> Option<PhysAddr>;
pub fn dtb() -> Option<&'static Fdt>;
```

## 4 ACPI tables (x86)

| Table | Use |
|---|---|
| RSDP | root pointer to RSDT/XSDT |
| XSDT | enumerate other tables |
| MADT | local APIC list (CPUs), IO-APICs, ints overrides; AP startup |
| FADT | reset register, sleep registers (we don't sleep); SCI int |
| MCFG | PCIe ECAM regions |
| SRAT | NUMA: cpu→node, mem→node |
| SLIT | NUMA distance matrix |
| HMAT | NUMA bandwidth/latency (v1.x) |
| PPTT | CPU topology (cache hierarchy) |
| HPET | sanity check; not used |

Skipped: DSDT, SSDT, ECDT, FACS (no S3), all _table-with-AML.

Tables checksummed; failures: log warn, fall back to safe defaults.

## 5 DT (arm)

Walked at boot from boot-handed phys ptr. Convert to in-memory tree via `fdt-rs`-style parse. Used to:
- Enumerate CPUs (`/cpus/cpu@N`).
- Find GIC nodes (`compatible = "arm,gic-v3"`).
- Find Generic Timer (`compatible = "arm,armv8-timer"`).
- Find PCIe host (`compatible = "pci-host-ecam-generic"`).
- Find UART for console (`stdout-path` chosen-node).

Published at `/sys/firmware/devicetree/base/` for userspace consumption.

## 6 Concurrency

Read-only post-init; lock-free.

## 7 Test contract (frozen)

- QEMU x86 `-machine q35` boots: MADT, MCFG, SRAT parsed; cpu count matches `-smp`.
- QEMU arm `-machine virt` boots: DT parsed; cpu count, GICv3 base, timer freq match qemu params.
- Bad table checksum: warn, continue.
- Mem map: every PMM-init region matches firmware-claimed RAM extent.

## 8 Failure modes

- No RSDP on x86: kassert (UEFI mandatory).
- DT root mismatch on arm: kassert.

## 9 Debug

`debug-fw`: dump every table header on boot; full DT walk dump.

## 10 Cross-spec

`20`/`21` (controllers from MADT/DT), `34` (MCFG/PCI nodes), `13` (CPU bring-up from MADT/`/cpus`), `19` (`/sys/firmware/`).

## 11 Open Questions

- ACPI on aarch64 (UEFI-shipped): support both DT and ACPI; pick per firmware advertisement.
- AML in v2: not committed. Userspace handles laptop power policies via tools instead.
