// Per-arch device-MMIO mapping bring-up smokes.
//
// Splices the 4 KiB Device-attr leaves we need (HPET + LAPIC on
// x86; GICD + GICC + PL011 on arm) into the live page tables via
// `hal_<arch>::vmm::map_device_4k`, then enables each device and
// optionally runs a polled-timer + IRQ smoke under the right
// `debug-<sub>` gate.
//
// All call sites are diagnostic / gated; the device-mapping calls
// themselves are always-on production bring-up. The actual
// per-arch IRQ infrastructure (LAPIC enable, GIC enable, IRQ
// periodic-timer arm/disarm) lives in `lapic.rs` / `gic.rs`.

use hal::{MmuOps, Pa, PageFlags, PageSize, Va};

#[cfg(target_arch = "aarch64")]
mod arm;
#[cfg(target_arch = "x86_64")]
mod x86;

#[cfg(target_arch = "aarch64")]
pub use arm::smoke_device_map_arm;
#[cfg(target_arch = "x86_64")]
pub use x86::smoke_device_map_x86;

/// Kernel device-mapping base VA. Per `21§5` we carve a 4 GiB
/// sub-region of L4 slot 0x1FE: `VA = KERNEL_DEVICE_BASE | (pa & 0xFFFFFFFF)`.
/// Disjoint from HHDM (L4[0..0x100]) and kernel image (L4[0x1FF]).
#[cfg(target_os = "oxide-kernel")]
pub const KERNEL_DEVICE_BASE: u64 = 0xffff_ff00_0000_0000;
#[cfg(target_os = "oxide-kernel")]
pub const ECAM_BASE_VA: u64 = 0xffff_fe00_0000_0000;
#[cfg(target_os = "oxide-kernel")]
const ECAM_BUS_BYTES: u64 = 0x10_0000;
#[cfg(target_os = "oxide-kernel")]
const ECAM_PAGE_BYTES: u64 = 0x1000;
#[cfg(target_os = "oxide-kernel")]
const ECAM_BLOCK_BYTES: u64 = 0x20_0000;

/// Device-MMIO leaf flags: writable kernel mapping, no-cache,
/// write-through (so x86 packs PCD|PWT = Strong UC; arm packs
/// AttrIdx=Device-nGnRnE), no exec. Equivalent to the device-leaf
/// bits the previous-generation `vmm::map_device_4k` packed
/// directly.
fn device_flags() -> PageFlags {
    // GLOBAL (Linux marks kernel mappings global; `20§5`): device MMIO lives in
    // the kernel-half that is copied into EVERY AS root, so its TLB entry should
    // survive CR3 switches rather than be re-walked through whatever user root
    // is live. This is GAP-2 defense-in-depth: it keeps the LAPIC-EOI
    // translation resident across the lazy-TLB CR3 the EOI runs under. Effective
    // on x86 only when CR4.PGE is enabled (PTE bit 8 is otherwise ignored —
    // harmless either way); on aarch64 device/kernel leaves are already global
    // (the nG bit is never set), so the flag is a no-op there.
    PageFlags::READ
        | PageFlags::WRITE
        | PageFlags::NO_CACHE
        | PageFlags::WRITE_THROUGH
        | PageFlags::GLOBAL
}

#[cfg(target_os = "oxide-kernel")]
unsafe fn map_ecam_window<M: MmuOps>(base_pa: u64, bus_cap: u16) {
    let mut off = 0u64;
    let total = (bus_cap as u64) * ECAM_BUS_BYTES;
    while off < total {
        let left = total - off;
        if ((base_pa + off) & (ECAM_BLOCK_BYTES - 1)) == 0
            && ((ECAM_BASE_VA + off) & (ECAM_BLOCK_BYTES - 1)) == 0
            && left >= ECAM_BLOCK_BYTES
        {
            // SAFETY: caller selected boot-only ECAM publication; PA/VA are
            // block-aligned and the whole block lies inside the MCFG window.
            unsafe {
                M::map(Va(ECAM_BASE_VA + off), Pa(base_pa + off), device_flags(), PageSize::P2M);
            }
            off += ECAM_BLOCK_BYTES;
        } else {
            // SAFETY: caller selected boot-only ECAM publication; this page is
            // inside the MCFG window and is mapped with device attributes.
            unsafe {
                M::map(Va(ECAM_BASE_VA + off), Pa(base_pa + off), device_flags(), PageSize::P4K);
            }
            off += ECAM_PAGE_BYTES;
        }
    }
}
