// Reversible x86 AP lifecycle over the retained INIT/SIPI startup tuple.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use power::hibernate::log::{self, CpuOffPhase, CpuOffResult};

use super::{oxide_ap_entry_64, oxide_ap_tramp, oxide_ap_tramp_cr3,
    oxide_ap_tramp_entry, oxide_ap_tramp_percpu, oxide_ap_tramp_stack,
    oxide_ap_tramp_cpu, TRAMP_PA};

pub(super) const AP_ONLINE_SPINS: u32 = 50_000_000;
static STACKS: [AtomicU64; cpu::MAX_CPUS] = [const { AtomicU64::new(0) }; cpu::MAX_CPUS];
static PERCPUS: [AtomicU64; cpu::MAX_CPUS] = [const { AtomicU64::new(0) }; cpu::MAX_CPUS];
static APIC_IDS: [AtomicU32; cpu::MAX_CPUS] = [const { AtomicU32::new(u32::MAX) }; cpu::MAX_CPUS];

/// Retain the successful cold-start tuple for later CPU-up. # C: O(1)
pub(super) fn retain(logical: usize, apic: u32, stack: u64, percpu: u64) {
    if logical >= cpu::MAX_CPUS { return; }
    STACKS[logical].store(stack, Ordering::Relaxed);
    PERCPUS[logical].store(percpu, Ordering::Relaxed);
    APIC_IDS[logical].store(apic, Ordering::Release);
}

/// Deliver the architecture INIT/SIPI sequence to one AP. # C: O(hardware wait)
pub(super) unsafe fn start_ap(id: u32) -> bool {
    let vec = (TRAMP_PA >> 12) as u8;
    // SAFETY: caller serialized trampoline fields and owns LAPIC startup.
    unsafe {
        if !send_init_sequence(id) { return false; }
        if !crate::lapic::write_icr(id, crate::lapic::icr_lo_sipi(vec)) { return false; }
        if !crate::lapic::wait_icr_idle_timeout() { return false; }
        crate::lapic::busy_wait_us(200);
        if !crate::lapic::write_icr(id, crate::lapic::icr_lo_sipi(vec)) { return false; }
        if !crate::lapic::wait_icr_idle_timeout() { return false; }
    }
    true
}

/// Linux `send_init_sequence()`: assert and then deassert a level-triggered
/// INIT, bounding both delivery-status waits. # C: O(10 ms + two safe waits)
unsafe fn send_init_sequence(id: u32) -> bool {
    // SAFETY: caller serializes LAPIC startup/hotplug for this destination.
    unsafe {
        if !crate::lapic::write_icr(id, crate::lapic::icr_lo_init_assert())
            || !crate::lapic::wait_icr_idle_timeout()
        {
            return false;
        }
        crate::lapic::busy_wait_us(10_000);
        if !crate::lapic::write_icr(id, crate::lapic::icr_lo_init_deassert()) {
            return false;
        }
        crate::lapic::wait_icr_idle_timeout()
    }
}

/// Reset an offlined AP into the architectural wait-for-SIPI state. # C: O(hardware wait)
unsafe fn confirm_dead(logical: usize) -> bool {
    let Some(id) = APIC_IDS.get(logical).map(|v| v.load(Ordering::Acquire)) else { return false; };
    if id == u32::MAX { return false; }
    // SAFETY: target published itself offline and is in CLI/HLT play-dead;
    // INIT is the architecture transition into wait-for-SIPI.
    // SAFETY: caller proved the target is in play-dead and owns hotplug.
    unsafe { send_init_sequence(id) }
}

/// Restart one previously offlined AP through the retained INIT/SIPI tuple.
/// # SAFETY: caller serializes CPU hotplug and `logical` is offline.
/// # C: O(hardware startup + bounded online wait)
unsafe fn restart_cpu(logical: u32) -> bool {
    let i = logical as usize;
    if i >= cpu::MAX_CPUS { return false; }
    let id = APIC_IDS[i].load(Ordering::Acquire);
    let stack = STACKS[i].load(Ordering::Relaxed);
    let percpu = PERCPUS[i].load(Ordering::Relaxed);
    if id == u32::MAX || stack == 0 || percpu == 0 { return false; }
    let hhdm = pmm::user_as::hhdm_offset();
    if hhdm == 0 { return false; }
    let tramp = (hhdm + TRAMP_PA) as *mut u8;
    // SAFETY: linked symbols identify fields within the reserved trampoline
    // page, and this is the sole CPU-up writer while the target is offline.
    unsafe {
        let base = &oxide_ap_tramp as *const u8 as usize;
        let cr3_off = &oxide_ap_tramp_cr3 as *const u8 as usize - base;
        let entry_off = &oxide_ap_tramp_entry as *const u8 as usize - base;
        let stack_off = &oxide_ap_tramp_stack as *const u8 as usize - base;
        let percpu_off = &oxide_ap_tramp_percpu as *const u8 as usize - base;
        let cpu_off = &oxide_ap_tramp_cpu as *const u8 as usize - base;
        let master = hal_x86_64::mmu_ops::kernel_master();
        let live = hal_x86_64::read_cr3();
        let cr3 = (if master != 0 { master } else { live }) & !(hal::PAGE_SIZE_BYTES - 1);
        core::ptr::write_volatile(tramp.add(cr3_off) as *mut u64, cr3);
        core::ptr::write_volatile(tramp.add(entry_off) as *mut u64, oxide_ap_entry_64 as *const () as u64);
        core::ptr::write_volatile(tramp.add(stack_off) as *mut u64, stack);
        core::ptr::write_volatile(tramp.add(percpu_off) as *mut u64, percpu);
        core::ptr::write_volatile(tramp.add(cpu_off) as *mut u64, logical as u64);
        if !start_ap(id) { return false; }
    }
    let mut spins = 0;
    while !cpu::smp::online_cpumask().contains(i) && spins < AP_ONLINE_SPINS {
        spins += 1; core::hint::spin_loop();
    }
    cpu::smp::online_cpumask().contains(i)
}

/// Offline every online secondary, rolling back successful prior transitions.
/// # C: O(N CPUs)
pub fn disable_secondary_cpus() -> bool {
    if !cpu::smp::begin_freeze() { return false; }
    let boot = cpu::logical_id_for_hardware(cpu::smp::boot_cpu_id()).unwrap_or(0) as usize;
    let online = cpu::smp::online_cpumask();
    for logical in (0..cpu::MAX_CPUS).rev() {
        if logical == boot || !online.contains(logical) { continue; }
        let cpu = logical as u32;
        log::cpu_off(cpu, CpuOffPhase::Request, CpuOffResult::Begin);
        if !cpu::smp::request_offline(cpu) {
            log::cpu_off(cpu, CpuOffPhase::Request, CpuOffResult::Refused);
            cpu::smp::cancel_offline(cpu); enable_secondary_cpus(); return false;
        }
        log::cpu_off(cpu, CpuOffPhase::Request, CpuOffResult::Ok);
        log::cpu_off(cpu, CpuOffPhase::Callfn, CpuOffResult::Begin);
        if !crate::call_fn::request_cpu_offline(cpu) {
            log::cpu_off(cpu, CpuOffPhase::Callfn, CpuOffResult::Refused);
            cpu::smp::cancel_offline(cpu); enable_secondary_cpus(); return false;
        }
        log::cpu_off(cpu, CpuOffPhase::Callfn, CpuOffResult::Ok);
        let mut spins = 0;
        while cpu::smp::offline_result(cpu).is_none() && spins < AP_ONLINE_SPINS {
            spins += 1; core::hint::spin_loop();
        }
        let result = cpu::smp::offline_result(cpu);
        if result != Some(true) {
            log::cpu_off(cpu, CpuOffPhase::OfflineResult,
                if result == Some(false) { CpuOffResult::Refused } else { CpuOffResult::Timeout });
            cpu::smp::cancel_offline(cpu); enable_secondary_cpus(); return false;
        }
        log::cpu_off(cpu, CpuOffPhase::OfflineResult, CpuOffResult::Ok);
        // SAFETY: successful target publication proves play-dead entry; INIT
        // completes x86's physical CPU-down half before snapshot work proceeds.
        log::cpu_off(cpu, CpuOffPhase::ConfirmDead, CpuOffResult::Begin);
        // SAFETY: the target published successful play-dead entry, so only
        // the hotplug coordinator can inspect its retained startup record.
        if !unsafe { confirm_dead(logical) } {
            log::cpu_off(cpu, CpuOffPhase::ConfirmDead, CpuOffResult::Refused);
            enable_secondary_cpus(); return false;
        }
        log::cpu_off(cpu, CpuOffPhase::ConfirmDead, CpuOffResult::Ok);
    }
    cpu::smp::online_count() == 1
}

/// Restart exactly the CPUs successfully frozen by the matching down pass.
/// # C: O(N CPUs)
pub fn enable_secondary_cpus() {
    let frozen = cpu::smp::frozen_cpumask();
    for logical in 0..cpu::MAX_CPUS {
        if frozen.contains(logical) {
            log::cpu_off(logical as u32, CpuOffPhase::Unwind, CpuOffResult::Begin);
            // SAFETY: frozen record proves this AP offline; thaw is sole owner.
            let online = unsafe { restart_cpu(logical as u32) };
            cpu::smp::finish_thaw_cpu(logical as u32, online);
            log::cpu_off(logical as u32, CpuOffPhase::Unwind,
                if online { CpuOffResult::Ok } else { CpuOffResult::Refused });
        }
    }
}
