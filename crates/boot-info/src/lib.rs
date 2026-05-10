// Boot-stub → kernel handoff types per `36` + `52§3` shared layer.
//
// Per-arch boot stubs (Limine on x86_64, EDK2/U-Boot DTB on aarch64)
// parse the bootloader-specific blob and hand the kernel one
// uniform `BootInfo`. Domain crates (pmm-setup, vmm, smp, time, etc.)
// consume fields off `BootInfo` directly so none of them have to
// pull in `kernel`.
//
// Pure types: no allocator, no syscall, no logging.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

/// Boot info passed by the arch boot stub.
///
/// Layout is bootloader-defined per `36`; the stub parses the
/// bootloader-specific blob (Limine info on x86_64, DTB/EDK2 on
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
    /// Higher-half direct-map offset (Limine HHDM, `36§3`). For any
    /// physical address `pa` covered by HHDM, the kernel-VA mirror
    /// is `hhdm_offset + pa`. `0` means the bootloader did not
    /// populate the HHDM response (early-boot diagnostics, hosted
    /// tests, or stub paths).
    pub hhdm_offset: u64,
    /// Physical address of the ACPI RSDP table, or 0 if the
    /// bootloader did not surface one (no UEFI / no ACPI on this
    /// platform).
    pub rsdp_pa: u64,
    /// Limine SMP response (x86_64): pointer to the
    /// `[*mut limine_proto::SmpInfoX86; smp_count]` array. `0`
    /// when running outside Limine or when the bootloader didn't
    /// populate the SMP response. Per `13§11` AP startup uses
    /// this to park `goto_address` per AP.
    pub smp_info_array: u64,
    /// Number of entries in `smp_info_array`. Includes the boot
    /// CPU; AP startup filters it via `bsp_lapic_id`.
    pub smp_count: u64,
    /// Boot CPU's APIC ID per Limine SMP response.
    pub bsp_lapic_id: u32,
    /// Padding so the C-layout end is 8-byte-aligned across both arches.
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
