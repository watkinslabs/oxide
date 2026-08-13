# Real-hardware bring-up — findings + work per system

Target: bare-metal x86_64 desktop/workstation (AMD Threadripper TRX40/WRX80/WRX90,
Intel i9 Z790/X870 class). Everything below is measured or read from this tree at
`7e9e57db3`, not assumed.

Scope: what stops the kernel booting and being usable on physical hardware. The
per-syscall overhead findings from the same session are a separate axis and are
not folded in here; only the SMP row overlaps.

## Run-time hardware audit

This ledger is a historical implementation assessment, not evidence that a
particular board has the required devices or bindings. Build an audit image
with `make hardware-audit-image-x86`; after Oxide has booted that root image on
the target machine, run `/usr/local/bin/oxide-hardware-audit` and capture its
serial output. Every record begins `OXIDE_HARDWARE_AUDIT|v1`; it inventories
firmware/ACPI, online CPUs, PCI IDs and bindings, storage, input, network, and
IOMMU groups. Its `driver-assessment` records identify native NVMe/AHCI
candidates, missing xHCI support, and physical NICs that need a Linux-module
compatibility-closure check.

The current x86 root mount selects only a virtio-blk disk with serial
`oxide-root`; the GRUB ISO is therefore not itself a turnkey bare-metal
installer. The audit command is deliberately manual and reports available
kernel state rather than claiming a successful physical install.

Status values: `OPEN` (no lane) | `CLAIMED <branch>` | `DONE <sha>`.

## 1 Summary table

Ordered by what stops you first. "Blocking" = the machine produces nothing
usable without it.

| Status | System | Blocking | Finding | Branch |
|---|---|---|---|---|
| DONE B1875 | Console (framebuffer) | no | Multiboot2 firmware scanout feeds the full VT/fbcon stack through a WC simple-framebuffer driver when no native fbdev binds. | B1875-physical-framebuffer-source |
| DONE | UEFI boot | no | x86 boots the hybrid GRUB ISO through either BIOS or UEFI firmware; both routes enter the same Multiboot2 handoff. | `make smoke-uefi-x86` |
| IN PROGRESS | Input | no | Native PCI xHCI enumerates USB hubs, HID keyboard/mouse and mass-storage protocol; physical-controller interoperability remains to be demonstrated. | `drv-xhci` |
| DONE 2b44a8a29 | Cache attributes (WC) | no | x86 PAT and arm64 Normal-NC are wired through driver-owned raw-PFN VMA policy. | B1874-x86-write-combining |
| DONE 18936f7b5, 667c8a2da | SMP AP bringup | no | x86 INIT/SIPI and arm64 PSCI paths bring APs into the scheduler. | F425/F428 |
| IN PROGRESS | x2APIC + CPU count | no¹ | `MAX_CPUS = 256` and the canonical online mask are multiword; x2APIC MSR transport is enabled before AP startup when VT-d exposes queued invalidation, interrupt remapping, and extended-interrupt mode. AMD-Vi remains limited to legacy remapped destinations. | `cpu`, `arch-irq`, `iommu` |
| OPEN | ACPI depth | no² | APIC/HPET/MCFG/SPCR parsed. No DSDT/AML, no FADT. | — |
| IN PROGRESS | Ethernet | no | Native e1000, 82574 e1000e, IGC, RTL8125 and AQC113 paths exist; each still needs hardware-specific traffic proof. | native PCI drivers |
| IN PROGRESS | IOMMU | no | AMD-Vi and VT-d initialize requester-keyed identity domains before PCI probing and invalidate each mapping mutation; fault handling and physical activation evidence remain. | `iommu` |
| IN PROGRESS | Storage | no | NVMe and AHCI bind by PCI class with DMA/IOMMU ownership; real controller reset, identify and sustained-I/O proof remain. | `drv-nvme`, `drv-ahci` |

¹ Not blocking on i9-class part counts; blocking on Threadripper.
² Not blocking for boot given the MSI-only constraint below; blocking for
poweroff/reset.

## 2 Console — the framebuffer chain

**Done B1875.** The Multiboot2 header requests the loader's preferred
framebuffer, and the same information-tag walk that owns the memory map and
RSDP now validates tag 8 and carries an optional packed-RGB mode on `BootInfo`.
Indexed and text modes are rejected rather than exposed with invented colour
semantics. The handoff retains physical base, pitch, dimensions, depth, and
all channel masks exactly.

`drv-simplefb` binds a platform resource only after PCI probing and only when
no native fbdev has registered. It maps the page-offset-aware aperture WC,
owns that mapping for the device lifetime, exposes the firmware format through
fbdev, and converts fbcon damage when the mode is not canonical XRGB8888.
Virtio-gpu remains the ordinary QEMU desktop path and its PMM-backed scanout
remains write-back.

Hosted tests cover handoff validation, RGB565 format retention and conversion,
pitch, damage bounds, and WC backing. Both release kernels build. A forced
QEMU std-VGA boot with virtio-gpu omitted registered the 1280x800 firmware
framebuffer and reached userspace with bidirectional serial. Repeated full-frame
writes measured 0.27 s WC versus 3.10 s under a temporary UC control; the
method and durable results are in `scratch/simplefb-performance-20260806.md`.

**Sequencing.** Do this BEFORE the UEFI port (§3), not after. GRUB fills
multiboot2 tag 8 on both BIOS and EFI — on EFI it takes the numbers from GOP
and passes them through the same tag. A simplefb driver written against tag 8
keeps working unchanged across the port. It is the piece that makes the port
debuggable, not throwaway work ahead of it.

**Dependency §5 is complete and consumed.** The simplefb driver selects the WC
policy, and its UC-versus-WC acceptance comparison is recorded.

## 3 UEFI boot

**Status.** The x86 image is a hybrid GRUB ISO: firmware may boot its BIOS
or UEFI entry, then GRUB supplies the same Multiboot2 memory map, RSDP and
framebuffer tags to the existing kernel handoff. No parallel EFI-stub parser
is required for x86. `make smoke-uefi-x86` pins the OVMF route; the same
artifact is suitable for UEFI-only physical firmware.

## 4 Input

**Status.** `drv-xhci` owns PCI host-controller reset, root hubs, USB device
enumeration, control and interrupt transfers, hub routing, HID keyboard/mouse
reports, and USB mass-storage transport. HID input enters the existing input
registry, so no PS/2 dependency remains for a normal board. The remaining
work is physical-controller and device interoperability evidence, not a
missing USB host stack.

## 5 Cache attributes — write-combining

**Done `2b44a8a29`.** `PageFlags::WRITE_COMBINE` selects the BSP/AP-owned PAT
WC entry on x86 and MAIR Normal-NC on aarch64. Raw-PFN VMAs retain one
driver-selected cache policy through every fault. PMM-backed virtio scanout
stays write-back; a firmware/MMIO framebuffer selects WC at registration, so
the driver remains the sole cache-policy owner.

Hosted regressions pin all three leaf policies and both architecture
encodings. Paired release boots and the exact Firefox no-regression workload
pass; `scratch/write-combining-performance-20260806.md` retains the numbers.
The UC-versus-WC full-screen fill belongs to §2's first physical framebuffer:
there is no device range to measure before that live blocker is implemented.

## 6 SMP AP bringup

**Done.** The audit followed the unused generic `cpu::smp::bring_up_aps`
scaffold and missed both live architecture owners. `kmain` calls
`arch_irq::smp_x86::bring_up_aps_x86` and
`hal_aarch64::smp::bring_up_aps_psci` directly.

x86 copies its 16-to-64-bit trampoline below 1 MiB, sends INIT/SIPI, waits for
arrival, and installs per-CPU GS, GDT/IDT/TSS, syscall and IRQ stacks, LAPIC
timer, runqueue, and online state. arm64 uses PSCI CPU_ON and joins the same
scheduler lifecycle. SMP=2 boot and watchdog output exercise both paths. The
remaining scale blocker is §7: platform-specific extended interrupt remapping
and physical scale evidence.

## 7 x2APIC and CPU count

**Current state.** `MAX_CPUS = 256`; the canonical online and transport masks
are multiword atomic bitmaps. MADT discovery preserves 32-bit APIC IDs, and
x2APIC MSR transport is selected on the BSP before AP startup only when the
CPU advertises x2APIC and the active VT-d units jointly provide queued
invalidation, interrupt remapping, and extended-interrupt mode. APs consume
that BSP decision before their first LAPIC register access.

The gate is necessary: a bare-metal PCI MSI or I/O-APIC destination cannot
address every x2APIC ID without an extended interrupt-remapping path. The
current AMD-Vi owner publishes only its legacy 32-bit requester interrupt table
and accepts an 8-bit destination ID. It must grow the extended table format and
the corresponding hardware enable sequence before x2APIC is selected on AMD
systems. Until then, xAPIC keeps those systems safe but limits addressable APIC
IDs to 255.

**Remaining work.**

1. Add AMD-Vi extended interrupt-table capability discovery, table layout,
   enablement and invalidation; carry a 32-bit APIC destination end-to-end.
2. Exercise both firmware-enabled and kernel-selected x2APIC on physical
   systems, including an AMD-Vi machine with APIC IDs above 255.
3. Confirm the MADT walk handles both Local APIC and Local x2APIC entry types
   without double-counting a CPU present in each.

## 8 ACPI depth

**Finding.** Parsed tables: APIC, HPET, MCFG, SPCR
(`crates/kernel/firmware/src/acpi/`). No DSDT/SSDT, no AML interpreter, no
FADT.

Two consequences:

- **No `_PRT`**, so legacy INTx routing cannot be resolved. Every device must
  use MSI or MSI-X. `crates/drivers/pci/src/caps.rs` has both cap decoders
  plus `program_msi_single` and the MSI-X table helpers, so this is workable —
  but it is a hard constraint on which devices can be supported, not a
  preference.
- **No FADT**, so no ACPI poweroff and no ACPI reset. `crates/kernel/power/`
  carries the `reboot(2)` policy (`cad.rs`) with no hardware path under it.

**Work.**

1. FADT parse → PM1a/PM1b control blocks → S5 poweroff and the reset register.
   Small, self-contained, and it makes the machine controllable.
2. Record the MSI-only constraint as a driver-model rule so a future driver
   does not quietly assume INTx.
3. AML interpreter: large. Not required for the systems in this document.
   Needed later for hotplug, thermal, and the power button.

## 9 Ethernet

**Status.** Native PCI paths exist for legacy Intel e1000, 82574 e1000e, IGC,
RTL8125 and AQC113. Each owns PCI bus mastering, DMA/IOMMU mapping and interrupt
delivery; the remaining requirement is traffic validation on its matching
physical silicon. Unsupported Intel e1000e families remain unbound until their
distinct PHY and reset contracts exist.

## 10 IOMMU

**Status.** AMD-Vi and VT-d retain firmware requester ownership, build one
identity domain per unit, attach requesters before PCI driver probing, and
invalidate every live mapping mutation. Fault reporting, capability-dependent
page-table depth and physical activation evidence remain required before this
path may be called fully hardware-proven.

## 11 Storage

**Finding.** Both drivers exist and bind by PCI class:
`drv-nvme` (`NVME_CLASS24 = 0x01_08_02`, 1161 lines) and
`drv-ahci` (`AHCI_CLASS24 = 0x01_06_01`, 2062 lines). PCI config access is
already ECAM (`crates/kernel/pci-boot/src/config_access.rs`), which is the
real-hardware path rather than legacy `0xCF8`.

**Work.** Validation, not construction: real controllers, real MSI-X vectors,
real queue depths, and the reset/identify paths against actual firmware.
Expect bugs; expect the shape to hold.

## 12 Suggested order

Each step is chosen so the next one is debuggable.

| Step | Item | Why here |
|---|---|---|
| 1 | Console framebuffer (§2) + WC (§5) | Nothing else is debuggable blind; survives the UEFI port unchanged |
| 2 | UEFI boot (§3) | Real firmware, with output already working |
| 3 | Storage validation (§11) | Root filesystem on real hardware |
| 4 | Input (§4) | Interactive at the console |
| 5 | SMP (§6) + x2APIC (§7) | Correctness first, then the other 63 cores |
| 6 | FADT poweroff (§8) | Controllable machine |
| 7 | Ethernet (§9) | Networked machine |

Steps 1-2 have no hardware dependency and are verifiable under QEMU with OVMF.

## 13 Open questions on the target machine

Answer before committing to a board — these change scope materially.

| Question | Changes |
|---|---|
| PS/2 port present? | §4 collapses to nothing, or becomes a phase |
| COM header wired to the legacy controller? | Early-panic visibility before §2 lands |
| Which NIC? | §9 |
| CSM available? | Whether §3 blocks step 1 |
| Core count | §7 urgency |

On the two parts named: the i9 is the lower-risk first target — smaller core
counts defer §6/§7, and consumer boards more often retain PS/2. Threadripper
forces both up front.
