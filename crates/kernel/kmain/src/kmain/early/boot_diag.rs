//! Firmware handoff diagnostics and topology identity publication.

use crate::BootInfo;
#[cfg(feature = "debug-pmm")]
use crate::BootMemRegion;

/// Echo the bootloader command line as one diagnostic record.
pub(super) fn log_cmdline() {
    // The slot already ends in newline; raw writes keep label and body in one
    // record instead of letting a level macro terminate between them.
    klog::write_raw(b"Kernel command line: ");
    klog::write_raw(crate::boot_cmdline::get());
}

pub(super) fn log(info: &BootInfo) {
    debug_boot! { klog::kinfo!("init started"); }
    debug_boot! {
        if info.hhdm_offset != 0 { klog::kinfo!("hhdm: present"); }
        else { klog::kinfo!("hhdm: absent"); }
    }
    if info.rsdp_pa != 0 {
        debug_acpi! {
            klog::write_raw(b"[INFO]  rsdp: ");
            klog::write_hex_u64(info.rsdp_pa);
            klog::write_raw(b"\n");
        }
        firmware::set_add_cpu_hook(cpu::add_cpu);
        // SAFETY: the bootloader retains the HHDM-mapped RSDP backing.
        unsafe { firmware::try_log_acpi(info.rsdp_pa, info.hhdm_offset); }
    } else {
        debug_boot! { klog::kinfo!("rsdp: absent"); }
    }
    #[cfg(target_arch = "x86_64")]
    // SAFETY: MADT production completed before this topology publication.
    unsafe { cpu::smp::set_boot_cpu_id(u64::from(info.bsp_lapic_id)); }
    debug_boot! {
        if info.framebuffer.byte_len().is_some() {
            klog::write_raw(b"[INFO]  bootfb: base=");
            klog::write_hex_u64(info.framebuffer.base_pa);
            klog::write_raw(b" width=");
            klog::write_dec_u64(info.framebuffer.width as u64);
            klog::write_raw(b" height=");
            klog::write_dec_u64(info.framebuffer.height as u64);
            klog::write_raw(b" pitch=");
            klog::write_dec_u64(info.framebuffer.pitch as u64);
            klog::write_raw(b" bpp=");
            klog::write_dec_u64(info.framebuffer.bpp as u64);
            klog::write_raw(b"\n");
        } else { klog::write_raw(b"[INFO]  bootfb: absent\n"); }
    }
    #[cfg(target_arch = "x86_64")]
    // SAFETY: legacy BIOS ROM window is retained HHDM-readable.
    unsafe { firmware::smbios::init_x86(info.hhdm_offset); }
    if info.memmap_count != 0 {
        debug_boot! { klog::kinfo!("memmap: present"); }
        debug_pmm! {
            // SAFETY: BootInfo guarantees this pointer/count pair for boot.
            let regions: &[BootMemRegion] = unsafe {
                core::slice::from_raw_parts(info.memmap_ptr, info.memmap_count as usize)
            };
            pmm::boot::log_memmap(regions);
        }
    } else { debug_boot! { klog::kinfo!("memmap: absent"); } }
}
