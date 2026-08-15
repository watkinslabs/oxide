use super::{device_flags, map_ecam_window, ECAM_BASE_VA, ECAM_WINDOW_BYTES, KERNEL_DEVICE_BASE};
use hal::{MmuOps, Pa, PageSize, Va};

/// HPET phys base on QEMU q35 (matches MADT log).
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
const HPET_PHYS: u64 = 0xfed0_0000;
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
const HPET_VA: u64 = KERNEL_DEVICE_BASE | (HPET_PHYS & 0xFFFF_FFFF);

/// LAPIC phys base (matches MADT `madt lapic_pa=…`).
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
const LAPIC_PHYS: u64 = 0xfee0_0000;
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
const LAPIC_VA: u64 = KERNEL_DEVICE_BASE | (LAPIC_PHYS & 0xFFFF_FFFF);

/// x86 device-MMIO bring-up smoke. Maps HPET + LAPIC at fixed
/// kernel-VA via `MmuOps::map` (per-arch impl in
/// `hal_x86_64::mmu_ops::X86Mmu`), enables LAPIC, runs the polled
/// + IRQ-driven timer smokes (gated `debug-vmm` / `debug-irq`).
/// # SAFETY: caller is the boot path; allocator up; PMM ready;
/// `mmu_ops::set_hhdm_offset` + `set_frame_alloc` already invoked
/// for x86; single-CPU; IRQs masked at entry.
/// # C: O(walk depth × 2) for the maps; spin loops dominate runtime.
/// # Ctx: pre-init, IRQ-off (entry), single-CPU
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
pub fn smoke_device_map_x86(_hhdm: u64) {
    use arch_irq::lapic;
    use hal_x86_64::mmu_ops::X86Mmu;
    // SAFETY: single-CPU, IRQs off, PMM owns its frames; we splice
    // a 4 KiB Device-attr leaf into the kernel-half of the live
    // PML4 via the live MmuOps state.
    unsafe { <X86Mmu as MmuOps>::map(Va(HPET_VA), Pa(HPET_PHYS), device_flags(), PageSize::P4K); }
    debug_vmm! {
        // SAFETY: HPET_VA was just mapped Device-attr; the read is
        // a volatile MMIO load of HPET_GCAP_ID at offset 0.
        let cap = unsafe { core::ptr::read_volatile(HPET_VA as *const u32) };
        klog::write_raw(b"[INFO]  device-map: hpet cap=");
        klog::write_hex_u64(cap as u64);
        klog::write_raw(b"\n");
    }

    // LAPIC enable. Map → set IA32_APIC_BASE.E + SVR.SW_ENABLE → log
    // APIC ID + version.
    // SAFETY: chosen kernel VA disjoint from existing mappings; phys
    // 0xFEE00000 is the standard LAPIC base from MADT.
    unsafe { <X86Mmu as MmuOps>::map(Va(LAPIC_VA), Pa(LAPIC_PHYS), device_flags(), PageSize::P4K); }
    // SAFETY: LAPIC_VA is freshly Device-attr mapped; single-CPU.
    let s = unsafe { lapic::enable(LAPIC_VA) };
    match s {
        lapic::LapicStatus::AlreadyOn => { debug_irq! { klog::kinfo!("lapic: already on"); } }
        lapic::LapicStatus::Enabled { apic_id: _apic_id, version: _version } => {
            debug_irq! {
                klog::write_raw(b"[INFO]  lapic: enabled apic_id=");
                klog::write_dec_u64(_apic_id as u64);
                klog::write_raw(b" version=");
                klog::write_hex_u64(_version as u64);
                klog::write_raw(b"\n");
                // Polled-timer smoke: verify count register decrements.
                // SAFETY: lapic::enable just succeeded so LAPIC is live.
                if let Some((a, b)) = unsafe { lapic::timer_smoke(0xFFFF_FFFF) } {
                    klog::write_raw(b"[INFO]  lapic: timer ");
                    klog::write_hex_u64(a as u64);
                    klog::write_raw(b" -> ");
                    klog::write_hex_u64(b as u64);
                    klog::write_raw(if b < a { b" (counting)\n" } else { b" (stuck)\n" });
                }
                // Keep this early smoke polled.  The boot CPU has not yet
                // installed its scheduler idle task, so it must not enable
                // timer delivery before the runtime scheduler phase.
            }
        }
    }

    let mut windows = [hal_x86_64::pci::EcamWindow {
        base_va: 0, segment: 0, bus_start: 0, bus_end: 0,
    }; pci::MAX_ECAM_WINDOWS];
    let count = firmware::acpi::ecam_window_count();
    for i in 0..count {
        let Some(w) = firmware::acpi::ecam_window(i) else { return };
        let bus_cap = u16::from(w.bus_end) - u16::from(w.bus_start) + 1;
        let base_va = ECAM_BASE_VA + (i as u64) * ECAM_WINDOW_BYTES;
        // SAFETY: ACPI MCFG provided this exact ECAM aperture; the bounded VA
        // slot is disjoint from every other aperture and maps it before PCI enum.
        let map_pa = w.base_pa + (u64::from(w.bus_start) << 20);
        unsafe { map_ecam_window::<X86Mmu>(base_va, map_pa, bus_cap); }
        windows[i] = hal_x86_64::pci::EcamWindow {
            base_va, segment: w.segment, bus_start: w.bus_start, bus_end: w.bus_end,
        };
    }
    if count != 0 { hal_x86_64::pci::publish_windows(&windows[..count]); }
}
