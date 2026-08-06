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
| OPEN | Console (framebuffer) | yes | Full VT/fbcon stack built; only producer of a framebuffer is virtio-gpu. No output on bare metal. | — |
| OPEN | UEFI boot | yes | x86 boots multiboot2 (BIOS/CSM) only. Modern boards are UEFI, many without CSM. | — |
| OPEN | Input | yes | Only PS/2 keyboard. No xHCI host controller anywhere. | — |
| OPEN | Cache attributes (WC) | yes¹ | No write-combining. Framebuffer would map Strong UC. | — |
| OPEN | SMP AP bringup | no | `bring_up_aps()` counts APs and returns; never starts one. Runs on 1 core. | — |
| OPEN | x2APIC + CPU count | no² | `MAX_CPUS = 64`, `u64` online mask, no x2APIC enablement. | — |
| OPEN | ACPI depth | no³ | APIC/HPET/MCFG/SPCR parsed. No DSDT/AML, no FADT. | — |
| OPEN | Ethernet | no | Only virtio-net. No driver for any physical NIC. | — |
| OPEN | IOMMU | no | Absent. Acceptable while disabled in firmware. | — |
| — | Storage | no | NVMe + AHCI drivers exist and match by PCI class. Needs hardware validation only. | — |

¹ Not blocking for boot; blocking for the console being usable rather than
merely present.
² Not blocking on i9-class part counts; blocking on Threadripper.
³ Not blocking for boot given the MSI-only constraint below; blocking for
poweroff/reset.

## 2 Console — the framebuffer chain

**Finding.** The VGA-text-console stack is complete and working: `fbcon`
(VT parser, 8x16 PSF font, damage tracking, vcrender), `vt` (vc, emulator,
cp437, palette, wide/EAW), `vtconsole`, `console/{vt_console,vt_tty,vcs,vt_input}`,
`fbdev` registry with `/dev/fbN` and the FBIO ioctls. It exercises correctly
under QEMU. Its only pixel source is a virtual device.

Four missing links, all at the bottom of the stack:

| # | Link | Evidence |
|---|---|---|
| 1 | Multiboot2 header never requests a framebuffer | `crates/arch/boot-x86_64/src/mb2.rs:52-68` emits entry-address (type 3) + end (type 0) only; no type-5 tag |
| 2 | Info parser discards the framebuffer tag | `mb2.rs:440-468` handles tag 6 (mmap) and 14\|15 (RSDP); `_ => {}` drops tag 8 |
| 3 | `BootInfo` has no framebuffer fields | `crates/shared/boot-info/src/lib.rs:21` — memmap, seed, boot_ns, hhdm_offset, rsdp_pa, bsp_lapic_id |
| 4 | Nothing but virtio-gpu registers a scanout | `fbdev::init_scanout` has one non-test caller: `crates/drivers/drv-virtio-gpu/src/post_init/scanout.rs:171` |

Consequence on bare metal: no virtio-gpu → no `init_scanout` → no fbdev → no
fbcon → no `/dev/tty0`. Serial is the only output path, and no modern desktop
board wires a 16550 at `0x3F8` (§4).

This is the machinery-without-callers class: a complete subsystem whose sole
producer is a virtual device.

**Work.**

1. Add the framebuffer request tag (type 5) to the multiboot2 header with
   width/height/depth 0 (loader's preferred mode).
2. Parse tag 8 (`framebuffer_common`) in the info walk: base, pitch, width,
   height, bpp, type. Reject indexed-colour and EGA-text types — take the RGB
   case only, and record which was refused.
3. Carry the fields on `BootInfo`. New fields are additive; the struct is
   shared with aarch64, so default them to "absent" rather than making the
   parse mandatory.
4. New `drv-simplefb`: consumes the `BootInfo` fields, maps the range, calls
   `fbdev::init_scanout`. No mode setting, no acceleration — the firmware mode
   is the only mode.
5. Register fbcon as a boot console early enough that panics before driver
   init reach the screen.

**Sequencing.** Do this BEFORE the UEFI port (§3), not after. GRUB fills
multiboot2 tag 8 on both BIOS and EFI — on EFI it takes the numbers from GOP
and passes them through the same tag. A simplefb driver written against tag 8
keeps working unchanged across the port. It is the piece that makes the port
debuggable, not throwaway work ahead of it.

**Depends on** §5 (write-combining) to be pleasant rather than merely present.

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

**Finding.** No write-combining anywhere. `hal::PageFlags`
(`crates/arch/hal/src/lib.rs:119-120`) offers `NO_CACHE` and `WRITE_THROUGH`
only — there is no `WRITE_COMBINE`. On x86, `PCD|PWT` resolves to PAT slot 3,
Strong UC (`crates/arch/hal-x86_64/src/vmm.rs:10-12`). The comment there
allows for "PAT slot 1 if the kernel has reprogrammed PAT", but nothing
programs `IA32_PAT` — grep returns no writer.

Consequence: a firmware framebuffer maps Strong UC. Every character cell
becomes a separate uncached write across PCIe. Scrolling a text console is
visibly slow; a desktop compositor on it is not viable.

**Work.**

1. Program `IA32_PAT` at boot to place WC in a known slot, on the BSP and on
   every AP as it comes up (the MSR is per-CPU).
2. Add `PageFlags::WRITE_COMBINE` and the per-arch leaf encoding. aarch64 has
   its own Normal-NC attribute — encode both rather than making the flag
   x86-only, per the lockstep rule.
3. Map the simplefb range WC.
4. Verify by measurement, not inspection: time a full-screen fill UC vs WC and
   record both numbers. A change this cheap to get wrong silently deserves a
   positive control.

## 6 SMP AP bringup

**Finding.** `crates/kernel/cpu/src/smp.rs:121` — `bring_up_aps()` calls
`enumerate_aps().len()` and returns the count. Its own doc comment says "v1
does no actual startup — the per-AP INIT-IPI / PSCI CPU_ON sequence lands in
P4-08+". No INIT-SIPI sequence exists; grep for SIPI/trampoline across
`crates/` finds no x86 AP entry path.

Consequence: one core, whatever the part. On a 64-core Threadripper that is
1/64 of the machine, and it compounds the separate per-syscall overhead
finding.

**Work.**

1. AP trampoline: real-mode entry page below 1 MiB, to protected then long
   mode, onto the shared page tables.
2. INIT-SIPI-SIPI per AP with the spec's delays; wait on the arrival ack
   (`ap_arrived()` already exists and increments `ONLINE`).
3. Per-CPU area, GDT/IDT/TSS, and syscall MSRs per AP — the syscall entry path
   reads `gs:[8]`/`gs:[16]` from the per-CPU base, so an AP without this
   faults on its first syscall.
4. Per-CPU PAT programming (§5).
5. Then re-check the locks the syscall path takes per call — a global registry
   lock that is uncontended at 1 core is a serialisation point at 64.

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
