// Boot-stub → kernel handoff types per `36` + `52§3` shared layer.
//
// Per-arch boot stubs (multiboot2 info on x86_64, EDK2/U-Boot DTB on
// aarch64) parse the bootloader-specific blob and hand the kernel one
// uniform `BootInfo`. Domain crates (pmm-setup, vmm, smp, time, etc.)
// consume fields off `BootInfo` directly so none of them have to
// pull in `kernel`.
//
// Pure types: no allocator, no syscall, no logging.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

mod framebuffer;
pub use framebuffer::{BootFramebuffer, BootFramebufferBitfield, BootFramebufferKind};

/// Boot info passed by the arch boot stub.
///
/// Layout is bootloader-defined per `36`; the stub parses the
/// bootloader-specific blob (multiboot2 info on x86_64, DTB/EDK2 on
/// aarch64) and hands a uniform view to the kernel.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct BootInfo {
    /// Number of memory map entries.
    pub memmap_count: u32,
    /// Pointer to a `[BootMemRegion; memmap_count]`.
    pub memmap_ptr: *const BootMemRegion,
    /// Bootloader-provided initial entropy (RDRAND on x86; RNDR on
    /// arm; bootloader-collected jitter as fallback).
    pub seed: [u8; 32],
    /// Boot-time monotonic counter snapshot in nanoseconds.
    pub boot_ns: u64,
    /// Higher-half direct-map offset installed by the boot stub's page
    /// tables (`36§3`). For any physical address `pa` covered by HHDM,
    /// the kernel-VA mirror is `hhdm_offset + pa`. `0` means no HHDM
    /// (early-boot diagnostics, hosted tests, or stub paths).
    pub hhdm_offset: u64,
    /// Physical address of the ACPI RSDP table, or 0 if the
    /// bootloader did not surface one (no UEFI / no ACPI on this
    /// platform).
    pub rsdp_pa: u64,
    /// Firmware/bootloader-owned linear framebuffer, or [`BootFramebuffer::EMPTY`]
    /// when the handoff did not provide a usable RGB mode.
    pub framebuffer: BootFramebuffer,
    /// Physical address of the flattened device tree the firmware handed the
    /// boot stub, or 0 when this platform provides none (x86_64, or an
    /// ACPI-only arm64 firmware). The blob is left where the firmware put it
    /// and carved out of the memmap as reserved, so it stays readable through
    /// the direct map for the life of the kernel — that is what lets the
    /// kernel publish the raw blob and the unflattened tree to userspace.
    pub dtb_pa: u64,
    /// Byte length of the retained device tree (`totalsize` from its header),
    /// 0 when `dtb_pa` is 0.
    pub dtb_len: u64,
    /// CRC32 (big-endian variant, seed `!0`) of the whole retained blob, taken
    /// by the boot stub at the moment it scanned the tree. The kernel re-takes
    /// it before publishing anything to userspace, so retention is verified
    /// rather than assumed (`36§4.1`): a tree that no longer matches what was
    /// scanned is not published at all.
    pub dtb_crc32: u32,
    /// Boot CPU's APIC id (x86_64) / MPIDR (aarch64). Neither live
    /// handoff carries a CPU table, so AP topology comes from the ACPI
    /// MADT / device tree and AP startup is the kernel's own (`13§11`).
    pub bsp_lapic_id: u32,
    /// Explicit tail padding, kept so the trailing `u32` group is spelled out
    /// rather than left to the compiler across both arches.
    pub _pad: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct BootMemRegion {
    pub base_pa: u64,
    pub len: u64,
    pub kind: BootMemKind,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum BootMemKind {
    Usable = 0,
    Reserved = 1,
    AcpiReclaim = 2,
    AcpiNvs = 3,
    BadMem = 4,
    BootloaderUsed = 5,
    KernelImage = 6,
    Initramfs = 7,
}
