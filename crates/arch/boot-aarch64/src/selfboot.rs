// aarch64 self-bootstrap boot path. QEMU `-machine virt
// -kernel <Image>` (and U-Boot `booti`) load a flat arm64 Image at RAM
// base 0x4000_0000 (text_offset 0) and jump to byte 0 with the MMU off,
// caches off, x0 = DTB phys, at EL2 (cortex-a72 on virt) or EL1.
//
// Byte 0 is the 64-byte arm64 Image header (Linux `Documentation/arm64/
// booting.rst`); its first word branches to `_arm_entry`, the MMU
// trampoline. The trampoline drops EL2->EL1 if needed, builds boot page
// tables, enables the MMU, jumps to the kernel's higher-half VMA, then
// tail-calls the shared `_start`.
//
// Address-space layout the boot page tables install (4 KiB granule,
// 48-bit VA; device space in 1 GiB level-1 blocks, RAM in 4 KiB leaves
// per `linear_map`):
//   TTBR0 (low / identity, VA[47]=0):
//     0..1 GiB    -> phys 0..1 GiB   Device-nGnRE (GIC, PL011 @0x0900_0000)
//     1..4 GiB    -> phys 1..4 GiB   Normal-WB     (RAM; kernel @0x4000_0000)
//   TTBR1 (high, VA[47]=1):
//     HHDM 0xFFFF_8000_0000_0000 -> phys 0   (reuses the TTBR0 ident L1:
//                                  device 0..1G, normal 1..4G)
//     KB   0xFFFF_FFFF_8000_0000 -> phys 0x4000_0000 (== KERNEL_PHYS) one
//                                  1 GiB Normal block covering the image.
// After the high jump TTBR0 is cleared (mirrors x86 PML4[0] teardown) so
// the kernel's per-process user mappings start from an empty low half.

#![cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]

use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

/// HHDM offset the trampoline installs (TTBR1 0xFFFF_8000… -> phys 0).
/// Mirrors the x86 `MB2_HHDM`; reported as `BootInfo.hhdm_offset` and
/// used by the PL011 driver to reach the UART after the MMU is on.
pub const ARM_SELFBOOT_HHDM: u64 = 0xFFFF_8000_0000_0000;

/// Set to 1 by the trampoline (after the high jump) when we booted via
/// the arm64 Image protocol. `_start_rust` reads it to pick
/// `ARM_SELFBOOT_HHDM` as the `BootInfo` HHDM offset.
#[no_mangle]
pub static SB_SELFBOOT_FLAG: AtomicU64 = AtomicU64::new(0);

/// Actual physical load base, recorded by the trampoline (`adrp
/// _arm_image_start`). QEMU loads the kernel 2 MiB above the RAM base
/// (it reserves the low 2 MiB for the DTB), so this is 0x4020_0000 on
/// `virt`, not the 0x4000_0000 RAM base. `build_selfboot_memmap` reserves
/// `[load_base, load_base+image_size)` so the PMM never clobbers the
/// loaded kernel — the bug that made baked `&str` pointers read zero.
#[no_mangle]
pub static SB_LOAD_BASE: AtomicU64 = AtomicU64::new(0);

/// ACPI RSDP physical address found in the EFI configuration table by
/// `efi_stub_setup` (gEfiAcpi20TableGuid), or 0 (booti/`-kernel` path, or no
/// ACPI). `build_boot_info` surfaces it as `BootInfo.rsdp_pa` so the kernel
/// decodes RSDP→XSDT→MCFG (PCI ECAM) + MADT — without it the EFI/GRUB arm
/// path has neither DTB nor ACPI, so PCI never enumerates (no GPU/display)
/// and CPUs can't be counted.
#[no_mangle]
pub static EFI_RSDP_PA: AtomicU64 = AtomicU64::new(0);

/// Max command-line bytes captured from the EFI loaded-image protocol's
/// `LoadOptions`. Sized to the kernel's cmdline storage bound.
pub const EFI_CMDLINE_MAX: usize = 2048;
/// UTF-8 command-line bytes decoded from `LoadOptions` by `efi_stub_setup`,
/// and their length. This is the ONLY transport carrying the bootloader
/// command line on the EFI arm path: the firmware publishes no device tree,
/// so there is no `/chosen/bootargs` for the bootloader to write into, and a
/// kernel that reads only the device tree silently ignores every parameter.
/// Zero length = the firmware supplied no load options.
pub static EFI_CMDLINE_LEN: AtomicU64 = AtomicU64::new(0);
pub static EFI_CMDLINE: [AtomicU8; EFI_CMDLINE_MAX] =
    [const { AtomicU8::new(0) }; EFI_CMDLINE_MAX];

/// Max `EfiConventionalMemory` regions captured from the EFI memory map by
/// `efi_stub_setup` for the no-DTB PMM memmap (QEMU EDK2 in ACPI mode hands
/// no FDT, so the DTB `/memory` extent is unavailable — without this the
/// kernel fell back to a hardcoded 1 GiB and ignored the rest of guest RAM).
pub const EFI_RAM_MAX: usize = 64;
/// Count of valid entries in `EFI_RAM_BASE`/`EFI_RAM_PAGES`.
pub static EFI_RAM_COUNT: AtomicU64 = AtomicU64::new(0);
/// Per-region base PA of each captured `EfiConventionalMemory` block.
pub static EFI_RAM_BASE: [AtomicU64; EFI_RAM_MAX] =
    [const { AtomicU64::new(0) }; EFI_RAM_MAX];
/// Per-region page count (4 KiB) of each captured block.
pub static EFI_RAM_PAGES: [AtomicU64; EFI_RAM_MAX] =
    [const { AtomicU64::new(0) }; EFI_RAM_MAX];
/// BootServices Code/Data (types 3/4) regions — reclaimable after
/// ExitBootServices, BUT this EDK2 stashes the live ACPI tables in type4.
/// They are added to the usable map ONLY once `build_selfboot_memmap` has
/// pinned the ACPI table extent as Reserved (else they corrupt ACPI →
/// pci devices=0). Captured separately from `EFI_RAM_*` for that gating.
pub static EFI_BS_COUNT: AtomicU64 = AtomicU64::new(0);
pub static EFI_BS_BASE: [AtomicU64; EFI_RAM_MAX] =
    [const { AtomicU64::new(0) }; EFI_RAM_MAX];
pub static EFI_BS_PAGES: [AtomicU64; EFI_RAM_MAX] =
    [const { AtomicU64::new(0) }; EFI_RAM_MAX];
/// Total pages per EFI memory type (0..=14), summed across the EFI memory
/// map by `efi_stub_setup`. Diagnostic: shows exactly where guest RAM goes
/// (firmware-reserved vs boot-services vs ACPI vs free conventional).
pub static EFI_TYPE_PAGES: [AtomicU64; 16] =
    [const { AtomicU64::new(0) }; 16];

/// True when we entered via the self-bootstrap Image trampoline.
/// # C: O(1)
pub fn is_selfboot() -> bool { SB_SELFBOOT_FLAG.load(Ordering::Acquire) != 0 }

mod asm;
mod efi;

pub use efi::efi_stub_setup;
