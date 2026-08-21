// Retained PSCI CPU-up records and cache publication for reversible hotplug.

use core::sync::atomic::{AtomicU64, Ordering};

use super::AP_ONLINE_SPINS;

struct RestartRecord { mpidr: AtomicU64, entry_pa: AtomicU64, boot_block_pa: AtomicU64 }
impl RestartRecord {
    const fn new() -> Self { Self { mpidr: AtomicU64::new(0), entry_pa: AtomicU64::new(0),
        boot_block_pa: AtomicU64::new(0) } }
}
static RESTART: [RestartRecord; cpu::MAX_CPUS] =
    [const { RestartRecord::new() }; cpu::MAX_CPUS];

/// Retain the successful initial CPU_ON tuple. # C: O(1)
pub(super) fn retain(logical: u32, mpidr: u64, entry_pa: u64, boot_block_pa: u64) {
    let Some(r) = RESTART.get(logical as usize) else { return; };
    r.mpidr.store(mpidr, Ordering::Relaxed);
    r.entry_pa.store(entry_pa, Ordering::Relaxed);
    r.boot_block_pa.store(boot_block_pa, Ordering::Release);
}

/// Clean a VA range to PoC before a caches-off PE consumes it.
/// # SAFETY: `va..va+len` is a live mapped kernel allocation.
/// # C: O(len / cache line)
pub(super) unsafe fn clean_dcache_to_poc(va: u64, len: usize) {
    const LINE: u64 = 64;
    let mut p = va & !(LINE - 1);
    let end = va + len as u64;
    while p < end {
        // SAFETY: p names a cache line in the caller-proven live mapping.
        unsafe { core::arch::asm!("dc cvac, {x}", x = in(reg) p, options(nostack, preserves_flags)); }
        p += LINE;
    }
    // SAFETY: orders all cleans before the subsequent PSCI CPU_ON.
    unsafe { core::arch::asm!("dsb sy", options(nostack, preserves_flags)); }
}

/// Restart one previously offlined PE through its retained PSCI CPU_ON tuple.
/// # SAFETY: caller serializes CPU hotplug and `logical` is offline.
/// # C: O(firmware transition + bounded online wait)
pub unsafe fn restart_cpu(logical: u32) -> bool {
    let Some(r) = RESTART.get(logical as usize) else { return false; };
    let bb = r.boot_block_pa.load(Ordering::Acquire);
    if bb == 0 { return false; }
    // SAFETY: retained record is the immutable tuple used for initial bring-up.
    let st = unsafe { crate::psci::cpu_on(r.mpidr.load(Ordering::Relaxed),
        r.entry_pa.load(Ordering::Relaxed), bb) };
    if st != crate::psci::PsciStatus::Success {
        return false;
    }
    let mut spins = 0;
    while !cpu::smp::online_cpumask().contains(logical as usize) && spins < AP_ONLINE_SPINS {
        spins += 1; core::hint::spin_loop();
    }
    cpu::smp::online_cpumask().contains(logical as usize)
}
