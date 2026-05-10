// CPU topology table per `13§11` / `20§7` / `21§7`. Populated
// during ACPI MADT decode at boot. Up to MAX_CPUS entries; the
// AP-startup path (P4-05+) reads this to know which APIC IDs to
// INIT/SIPI on x86 or PSCI CPU_ON on aarch64.
//
// v1 storage: AtomicU32 array + AtomicU32 count. Single-writer
// (boot CPU during ACPI walk); readers come up post-init when
// the count is stable. Lock-free.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use core::sync::atomic::{AtomicU32, Ordering};

/// Hard cap. Linux x86 default is 8192 (NR_CPUS); v1 picks 64
/// because we have no realistic test box that exceeds 32. The
/// constant is the only place this changes.
pub const MAX_CPUS: usize = 64;

// Parallel atomic arrays — keeps the table `Sync` without a
// Spinlock wrapper. `IDS[i] == u32::MAX` ⇒ slot empty.
static IDS:   [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(u32::MAX) }; MAX_CPUS];
static FLAGS: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(0)        }; MAX_CPUS];
static COUNT: AtomicU32             = AtomicU32::new(0);

/// MADT type-0 / type-9 / type-11 flags bit 0 = "enabled".
/// Inserted CPUs marked as enabled are bring-up-eligible.
pub const FLAG_ENABLED:        u32 = 1 << 0;
/// Bit 1 = "online-capable" (modern MADT). Treat as enabled if
/// firmware reports it; AP startup still defers to FLAG_ENABLED
/// for v1 — out-of-band hotplug is not on the v1 roadmap.
pub const FLAG_ONLINE_CAPABLE: u32 = 1 << 1;

/// Add a CPU entry. Returns false if the table is full (cap hit)
/// or the entry is already present. Boot-only.
///
/// # SAFETY: caller is the boot path, single-threaded ACPI walk.
/// # C: O(N_cpus)
pub unsafe fn add_cpu(apic_or_mpidr_id: u32, flags: u32) -> bool {
    if apic_or_mpidr_id == u32::MAX { return false; }
    // Dedup against prior inserts.
    let n = COUNT.load(Ordering::Acquire) as usize;
    for i in 0..n {
        if IDS[i].load(Ordering::Acquire) == apic_or_mpidr_id {
            return false;
        }
    }
    if n >= MAX_CPUS { return false; }
    IDS[n].store(apic_or_mpidr_id, Ordering::Release);
    FLAGS[n].store(flags, Ordering::Release);
    COUNT.store((n + 1) as u32, Ordering::Release);
    true
}

/// Count of inserted CPU entries. Includes disabled-but-present
/// entries; callers that want bring-up candidates filter on
/// `FLAG_ENABLED`.
/// # C: O(1)
pub fn count() -> u32 { COUNT.load(Ordering::Acquire) }

/// True iff at least one entry has been inserted (the boot CPU
/// is added by ACPI walk, so this also gates "ACPI parsed").
/// # C: O(1)
pub fn populated() -> bool { count() > 0 }

/// Read entry `idx`. Returns `(id, flags)` or `None` past the
/// inserted count.
/// # C: O(1)
pub fn get(idx: usize) -> Option<(u32, u32)> {
    if idx >= count() as usize { return None; }
    Some((
        IDS[idx].load(Ordering::Acquire),
        FLAGS[idx].load(Ordering::Acquire),
    ))
}

/// Number of entries with `FLAG_ENABLED` set (i.e. bring-up
/// candidates including the boot CPU). `13§11` / `00§3` cap on
/// what `cpu_count()` should report once SMP enumeration is wired.
/// # C: O(N_cpus)
pub fn enabled_count() -> u32 {
    let n = count() as usize;
    let mut c = 0u32;
    for i in 0..n {
        let f = FLAGS[i].load(Ordering::Acquire);
        if (f & (FLAG_ENABLED | FLAG_ONLINE_CAPABLE)) != 0 { c += 1; }
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reset() {
        // Clear by writing u32::MAX to all slots and zeroing count.
        // Hosted-test helper only — production never resets the table.
        for i in 0..MAX_CPUS {
            IDS[i].store(u32::MAX, Ordering::Release);
            FLAGS[i].store(0, Ordering::Release);
        }
        COUNT.store(0, Ordering::Release);
    }

    #[test]
    fn empty_table_has_no_cpus() {
        reset();
        assert_eq!(count(), 0);
        assert!(!populated());
        assert_eq!(enabled_count(), 0);
        assert!(get(0).is_none());
    }

    #[test]
    fn add_cpu_grows_count() {
        reset();
        // SAFETY: hosted test owns the table single-threadedly via reset()+sequential calls.
        unsafe { assert!(add_cpu(0, FLAG_ENABLED)); }
        // SAFETY: same — sequential second insert under the hosted-test single-thread invariant.
        unsafe { assert!(add_cpu(1, FLAG_ENABLED)); }
        assert_eq!(count(), 2);
        assert_eq!(get(0), Some((0, FLAG_ENABLED)));
        assert_eq!(get(1), Some((1, FLAG_ENABLED)));
        assert_eq!(enabled_count(), 2);
    }

    #[test]
    fn add_cpu_dedups() {
        reset();
        // SAFETY: hosted test owns the table single-threadedly via reset() + sequential calls.
        unsafe { assert!(add_cpu(7, FLAG_ENABLED)); }
        // SAFETY: same — second insert with the same id should be rejected.
        unsafe { assert!(!add_cpu(7, FLAG_ENABLED)); }
        assert_eq!(count(), 1);
    }

    #[test]
    fn add_cpu_rejects_sentinel() {
        reset();
        // SAFETY: hosted test owns the table; u32::MAX is the empty-slot sentinel and must be rejected.
        unsafe { assert!(!add_cpu(u32::MAX, FLAG_ENABLED)); }
        assert_eq!(count(), 0);
    }

    #[test]
    fn enabled_count_filters_disabled() {
        reset();
        // SAFETY: hosted test owns the table single-threadedly via reset() + sequential calls.
        unsafe {
            assert!(add_cpu(0, FLAG_ENABLED));
            assert!(add_cpu(1, 0));                       // disabled
            assert!(add_cpu(2, FLAG_ONLINE_CAPABLE));    // hot-plug-capable
        }
        assert_eq!(count(), 3);
        assert_eq!(enabled_count(), 2);
    }
}


pub mod smp;
