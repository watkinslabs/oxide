use super::{device_flags, map_ecam_window, ECAM_BASE_VA, KERNEL_DEVICE_BASE};
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
                // Periodic timer + STI: take real timer IRQs at
                // vec 0x40 for a brief observation window.
                let pre = lapic::TICK_COUNT.load(core::sync::atomic::Ordering::Relaxed);
                // SAFETY: LAPIC enabled, IDT[0x40] -> IRQ stub
                // (per #124), oxide_irq_dispatch handles EOI.
                if unsafe { lapic::timer_periodic(1_000_000) } {
                    // SAFETY: STI legal at CPL=0; pairs with the
                    // CLI below; ticks fire during the spin.
                    unsafe { core::arch::asm!("sti", options(nomem, nostack)); }
                    for _ in 0..10_000_000 { core::hint::spin_loop(); }
                    // SAFETY: CLI restores the pre-STI state
                    // (IF clear) before further bring-up steps.
                    unsafe { core::arch::asm!("cli", options(nomem, nostack)); }
                    // Disarm the periodic timer post-smoke. Under TCG
                    // the inter-tick gap is generous so a leftover armed
                    // timer mostly hits CLI-masked windows; under KVM
                    // (in-kernel irqchip + accurate TSC) the timer
                    // keeps posting into the IRR and the very next STI
                    // (e.g. before run_as_task's first schedule()) drops
                    // an IRQ flood. The canary / preempt smokes downstream
                    // re-arm + disarm cleanly per their own contracts.
                    // SAFETY: same LAPIC mapping as timer_periodic; idempotent stop of the periodic vector.
                    unsafe { lapic::timer_disarm(); }
                }
                let post = lapic::TICK_COUNT.load(core::sync::atomic::Ordering::Relaxed);
                klog::write_raw(b"[INFO]  lapic: timer ticks=");
                klog::write_dec_u64(post.wrapping_sub(pre));
                klog::write_raw(b"\n");
            }
        }
    }

    let ecam_pa = firmware::acpi::ECAM_BASE_PA
        .load(core::sync::atomic::Ordering::Acquire);
    let ecam_bus_cap = firmware::acpi::ecam_bus_cap();
    if ecam_pa != 0 && ecam_bus_cap != 0 {
        // SAFETY: ACPI MCFG provided the ECAM physical aperture; this boot-only
        // mapping publishes Device-attr config-space MMIO before PCI enum.
        unsafe { map_ecam_window::<X86Mmu>(ecam_pa, ecam_bus_cap); }
        hal_x86_64::pci::ECAM_BASE_VA
            .store(ECAM_BASE_VA, core::sync::atomic::Ordering::Release);
    }
}
