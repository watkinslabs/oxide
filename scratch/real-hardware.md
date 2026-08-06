# Real-hardware bring-up — findings + work per system

Target: bare-metal x86_64 desktop/workstation (AMD Threadripper TRX40/WRX80/WRX90,
Intel i9 Z790/X870 class). Everything below is measured or read from this tree at
`7e9e57db3`, not assumed.

Scope: what stops the kernel booting and being usable on physical hardware. The
per-syscall overhead findings from the same session are a separate axis and are
not folded in here; only the SMP row overlaps.

Status values: `OPEN` (no lane) | `CLAIMED <branch>` | `DONE <sha>`.

## 1 Summary table

Ordered by what stops you first. "Blocking" = the machine produces nothing
usable without it.

| Status | System | Blocking | Finding | Branch |
|---|---|---|---|---|
| DONE B1875 | Console (framebuffer) | no | Multiboot2 firmware scanout feeds the full VT/fbcon stack through a WC simple-framebuffer driver when no native fbdev binds. | B1875-physical-framebuffer-source |
| OPEN | UEFI boot | yes | x86 boots multiboot2 (BIOS/CSM) only. Modern boards are UEFI, many without CSM. | — |
| OPEN | Input | yes | Only PS/2 keyboard. No xHCI host controller anywhere. | — |
| DONE 2b44a8a29 | Cache attributes (WC) | no | x86 PAT and arm64 Normal-NC are wired through driver-owned raw-PFN VMA policy. | B1874-x86-write-combining |
| DONE 18936f7b5, 667c8a2da | SMP AP bringup | no | x86 INIT/SIPI and arm64 PSCI paths bring APs into the scheduler. | F425/F428 |
| OPEN | x2APIC + CPU count | no¹ | `MAX_CPUS = 64`, `u64` online mask, no x2APIC enablement. | — |
| OPEN | ACPI depth | no² | APIC/HPET/MCFG/SPCR parsed. No DSDT/AML, no FADT. | — |
| OPEN | Ethernet | no | Only virtio-net. No driver for any physical NIC. | — |
| OPEN | IOMMU | no | Absent. Acceptable while disabled in firmware. | — |
| — | Storage | no | NVMe + AHCI drivers exist and match by PCI class. Needs hardware validation only. | — |

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

**Finding.** x86 stages a `multiboot2` GRUB entry
(`tools/xtask/src/image_qemu/x86_64.rs:23-24`) — BIOS/CSM. TRX40/WRX80/WRX90
and Z790/X870-class boards are UEFI; many have dropped CSM entirely. aarch64
already boots EFI-stub, so the pattern exists in-tree.

**Work.**

1. GRUB EFI image alongside the BIOS one; `xtask` grows an EFI staging path.
2. EFI memory map → `BootMemRegion` conversion, replacing the multiboot2 tag-6
   walk. Kind mapping differs from the multiboot2 kinds already handled at
   `mb2.rs:365-369`; EFI conventional/loader/boot-services-reclaimable each map
   differently, and boot-services memory is only reclaimable after
   ExitBootServices.
3. RSDP from the EFI configuration table rather than tags 14/15.
4. Keep the tag-8 framebuffer path from §2 — GRUB supplies it on EFI too.
5. Verify both firmware paths still boot under QEMU (OVMF for the EFI side)
   before touching hardware.

## 4 Input

**Finding.** `crates/drivers/drv-ps2-keyboard` is the only physical input
driver. `crates/kernel/modules/src/linux_usb/` is a module-registry shim
(types/core/gadget, 945 lines) — no host controller. Grep for xHCI across
`crates/` returns nothing.

Consequence: no USB keyboard, no USB storage, no USB anything. Many
Threadripper and workstation boards still expose a PS/2 port, which sidesteps
this entirely for bring-up; most consumer i9 boards do not.

**Work.** Two paths, pick by board:

- *Board has PS/2*: nothing. Confirm the port is wired to the legacy
  controller and not an internal USB bridge — some boards emulate it.
- *No PS/2*: xHCI host controller + USB core (device enumeration, control
  transfers, interrupt endpoints) + HID boot-protocol keyboard. This is the
  single largest item in this document — treat it as its own phase, not a
  task. Feed it into the existing `input` registry so the VT input path
  (`console/vt_input.rs`) is unchanged.

**Board-selection note.** Whether the target board has PS/2 changes the scope
of real-hardware bring-up by months. Establish this before committing to a
machine.

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
remaining scale blocker is §7: the 64-CPU mask and lack of x2APIC.

## 7 x2APIC and CPU count

**Finding.** `crates/kernel/cpu/src/lib.rs:20` — `MAX_CPUS = 64`, and
`smp.rs` tracks liveness in a `u64` mask. MADT decode already reads x2APIC
entries (`crates/kernel/firmware/src/acpi/tables.rs:123-133`), but nothing
enables x2APIC MSR mode.

A Threadripper 7980X is 64C/128T — at or over the mask width. APIC IDs above
255 require x2APIC; xAPIC cannot address them.

**Work.**

1. Widen the online mask from `u64` to a bitmap; raise `MAX_CPUS` past 128.
   Audit every consumer of `online_mask()` for the `u64` assumption.
2. Enable x2APIC via `IA32_APIC_BASE` and switch LAPIC access from MMIO to
   MSR when firmware reports it.
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

**Finding.** `crates/drivers/drv-virtio-net` only. No driver for any physical
NIC.

Likely silicon by board class: Intel I225/I226, Realtek RTL8125, Aquantia
AQC113 on high-end Threadripper boards, Intel X550 on workstation boards.

**Work.** One driver, chosen by the target board. All are MSI-X capable, which
satisfies the §8 constraint. Pick the board partly by which NIC you are willing
to write.

## 10 IOMMU

**Finding.** Absent — no AMD-Vi, no VT-d, no DMAR/IVRS parse.

**Work.** None for bring-up. Devices DMA to physical addresses. Confirm
firmware does not hand over a pre-enabled IOMMU, which would silently drop
every DMA. Revisit when the driver set is stable.

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
