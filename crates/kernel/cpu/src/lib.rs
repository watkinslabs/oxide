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

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

pub mod mask;
pub use mask::{AtomicCpuMask, CpuMask};

/// Logical CPU admission cap shared with every per-CPU owner.
pub use hal::MAX_CPUS;
/// Offset in every architecture per-CPU page used by Linux module code.
pub const LINUX_MODULE_PERCPU_OFFSET: usize = 16;
/// Module per-CPU allocations reserve one page per logical CPU.
pub const LINUX_MODULE_PERCPU_STRIDE: usize = 4096;
/// Native driver NUMA-node slot in each architecture per-CPU page.
pub const LINUX_NUMA_NODE_OFFSET: usize = 64;
/// Native network softnet-data ABI view in each architecture per-CPU page.
pub const LINUX_SOFTNET_DATA_OFFSET: usize = 128;
/// Bytes reserved for one native softnet-data ABI view.
pub const LINUX_SOFTNET_DATA_BYTES: usize = 1088;
const _: () = assert!(LINUX_SOFTNET_DATA_OFFSET + LINUX_SOFTNET_DATA_BYTES <= LINUX_MODULE_PERCPU_STRIDE);

// Parallel atomic arrays — keeps the table `Sync` without a
// Spinlock wrapper. `IDS[i] == u64::MAX` ⇒ slot empty. Arm MPIDR affinity
// includes up to four levels, so truncating it to an APIC-sized value aliases
// otherwise distinct CPU nodes.
static IDS:   [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(u64::MAX) }; MAX_CPUS];
static FLAGS: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(0)        }; MAX_CPUS];
/// ACPI's logical-processor identifier. It is distinct from an x2APIC ID,
/// and is how a Processor object or CPU Device's `_UID` joins this topology.
static ACPI_UIDS: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(u32::MAX) }; MAX_CPUS];
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
pub unsafe fn add_cpu(apic_or_mpidr_id: u64, flags: u32, acpi_uid: u32) -> bool {
    if apic_or_mpidr_id == u64::MAX { return false; }
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
    ACPI_UIDS[n].store(acpi_uid, Ordering::Release);
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
pub fn get(idx: usize) -> Option<(u64, u32)> {
    if idx >= count() as usize { return None; }
    Some((
        IDS[idx].load(Ordering::Acquire),
        FLAGS[idx].load(Ordering::Acquire),
    ))
}

/// Translate a dense logical CPU index into its firmware/hardware id
/// (x86 APIC id, arm MPIDR affinity value). Scheduler and procfs state
/// use dense logical ids; arch interrupt controllers use this hardware id.
/// # C: O(1)
pub fn hardware_id_for_logical(cpu: u32) -> Option<u64> {
    get(cpu as usize).map(|(id, _)| id)
}

/// Translate a firmware/hardware id (x86 APIC id, arm MPIDR affinity value)
/// into the dense logical CPU index used by scheduler/per-CPU arrays.
/// # C: O(N_cpus)
pub fn logical_id_for_hardware(id: u64) -> Option<u32> {
    let n = count() as usize;
    for i in 0..n {
        if IDS[i].load(Ordering::Acquire) == id {
            return Some(i as u32);
        }
    }
    None
}

/// Translate an ACPI `Processor` ID or CPU-device `_UID` into the dense
/// logical index. CPU performance objects name this UID, while interrupt
/// routing names the APIC ID, so treating either as the other misbinds x2APIC
/// machines. # C: O(N_cpus)
pub fn logical_id_for_acpi_uid(uid: u32) -> Option<u32> {
    let n = count() as usize;
    for i in 0..n {
        if ACPI_UIDS[i].load(Ordering::Acquire) == uid { return Some(i as u32); }
    }
    None
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

    #[test]
    fn topology_arrays_use_canonical_cpu_bound() {
        assert_eq!(IDS.len(), hal::MAX_CPUS);
        assert_eq!(FLAGS.len(), hal::MAX_CPUS);
        assert_eq!(ACPI_UIDS.len(), hal::MAX_CPUS);
    }

    fn reset() {
        // Clear by writing u64::MAX to all slots and zeroing count.
        // Hosted-test helper only — production never resets the table.
        for i in 0..MAX_CPUS {
            IDS[i].store(u64::MAX, Ordering::Release);
            FLAGS[i].store(0, Ordering::Release);
            ACPI_UIDS[i].store(u32::MAX, Ordering::Release);
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
        unsafe { assert!(add_cpu(0, FLAG_ENABLED, 3)); }
        // SAFETY: same — sequential second insert under the hosted-test single-thread invariant.
        unsafe { assert!(add_cpu(1, FLAG_ENABLED, 9)); }
        assert_eq!(count(), 2);
        assert_eq!(get(0), Some((0, FLAG_ENABLED)));
        assert_eq!(get(1), Some((1, FLAG_ENABLED)));
        assert_eq!(logical_id_for_acpi_uid(9), Some(1));
        assert_eq!(enabled_count(), 2);
    }

    #[test]
    fn add_cpu_dedups() {
        reset();
        // SAFETY: hosted test owns the table single-threadedly via reset() + sequential calls.
        unsafe { assert!(add_cpu(7, FLAG_ENABLED, 7)); }
        // SAFETY: same — second insert with the same id should be rejected.
        unsafe { assert!(!add_cpu(7, FLAG_ENABLED, 7)); }
        assert_eq!(count(), 1);
    }

    #[test]
    fn add_cpu_rejects_sentinel() {
        reset();
        // SAFETY: hosted test owns the table; u32::MAX is the empty-slot sentinel and must be rejected.
        unsafe { assert!(!add_cpu(u64::MAX, FLAG_ENABLED, 0)); }
        assert_eq!(count(), 0);
    }

    #[test]
    fn translates_logical_and_hardware_ids() {
        reset();
        // SAFETY: hosted test owns the table single-threadedly via reset() + sequential calls.
        unsafe {
            assert!(add_cpu(0, FLAG_ENABLED, 0));
            assert!(add_cpu(2, FLAG_ENABLED, 2));
            assert!(add_cpu(6, FLAG_ENABLED, 6));
        }
        assert_eq!(hardware_id_for_logical(1), Some(2));
        assert_eq!(hardware_id_for_logical(3), None);
        assert_eq!(logical_id_for_hardware(6), Some(2));
        assert_eq!(logical_id_for_hardware(5), None);
        assert_eq!(logical_id_for_acpi_uid(2), Some(1));
        assert_eq!(logical_id_for_acpi_uid(5), None);
    }

    #[test]
    fn full_mpidr_affinity_does_not_alias_its_low_word() {
        reset();
        let mpidr = 0x0000_0001_0000_0002u64;
        // SAFETY: hosted test owns the table single-threadedly via reset() + insertion.
        unsafe { assert!(add_cpu(mpidr, FLAG_ENABLED, 4)); }
        assert_eq!(hardware_id_for_logical(0), Some(mpidr));
        assert_eq!(logical_id_for_hardware(mpidr), Some(0));
        assert_eq!(logical_id_for_hardware(2), None);
    }

    #[test]
    fn enabled_count_filters_disabled() {
        reset();
        // SAFETY: hosted test owns the table single-threadedly via reset() + sequential calls.
        unsafe {
            assert!(add_cpu(0, FLAG_ENABLED, 0));
            assert!(add_cpu(1, 0, 1));                       // disabled
            assert!(add_cpu(2, FLAG_ONLINE_CAPABLE, 2));    // hot-plug-capable
        }
        assert_eq!(count(), 3);
        assert_eq!(enabled_count(), 2);
    }
}


pub mod smp;

/// Cross-CPU call-function queue protocol — the ungated decision half of the
/// IPI mechanism whose arch driver lives in `arch-irq`.
pub mod call_fn;
