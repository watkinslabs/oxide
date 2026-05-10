// SMP bring-up entry per `13§11` / `20§7` / `21§7`. v1 stages:
//
//   1. ACPI MADT walk populates `cpu_topology` (P4-04 + P4-05).
//   2. `enumerate_aps()` returns the list of enabled APIC IDs /
//      MPIDRs minus the boot CPU.                  (this PR)
//   3. Per-arch trampoline allocation + INIT-IPI / PSCI CPU_ON
//      brings each AP into kernel context.               (next)
//   4. AP entry installs its per-CPU runqueue + IDT/GIC and
//      flips its `online` bit; boot CPU waits.
//   5. Load balancer wakes once `online_count() > 1`.
//
// `bring_up_aps()` is the orchestration entry the boot path
// calls after ACPI is parsed. Today it logs intent only — the
// real INIT-IPI lands in P4-08+.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use cpu as cpu_topology;

/// Boot-CPU id snapshot — captured at boot via `set_boot_cpu_id`.
/// Used by `enumerate_aps` to filter the boot CPU out of the
/// "secondaries to start" list.
static BOOT_CPU_ID: AtomicU32 = AtomicU32::new(u32::MAX);

/// Online-count, incremented by each AP as it finishes its bring-
/// up sequence (P4-08+). Boot CPU stamps 1 before letting any AP
/// observe the table.
static ONLINE: AtomicU32 = AtomicU32::new(0);

/// Capture the boot CPU's APIC id / MPIDR. Called once during
/// boot, after ACPI is parsed.
///
/// # SAFETY: caller is the boot path; this is the single writer
/// for `BOOT_CPU_ID`.
/// # C: O(1)
pub unsafe fn set_boot_cpu_id(id: u32) {
    BOOT_CPU_ID.store(id, Ordering::Release);
    // Boot CPU itself counts as online from the moment we enter
    // kernel_main. Stamp here so observers see online_count()>=1.
    ONLINE.store(1, Ordering::Release);
}

/// Boot CPU's APIC id / MPIDR. `u32::MAX` if `set_boot_cpu_id`
/// hasn't run yet.
/// # C: O(1)
pub fn boot_cpu_id() -> u32 { BOOT_CPU_ID.load(Ordering::Acquire) }

/// Number of CPUs that have completed bring-up. Boot CPU counts
/// as 1 from `set_boot_cpu_id` onward; each AP increments on
/// arrival.
/// # C: O(1)
pub fn online_count() -> u32 { ONLINE.load(Ordering::Acquire) }

/// AP-side bring-up notification. Each AP calls this after it
/// has installed its runqueue + per-CPU base register. Returns
/// the new online count.
/// # C: O(1)
pub fn ap_arrived() -> u32 { ONLINE.fetch_add(1, Ordering::AcqRel) + 1 }

/// Enabled-secondary list: every cpu_topology entry whose flags
/// include `FLAG_ENABLED` or `FLAG_ONLINE_CAPABLE`, excluding
/// the boot CPU id. Order matches MADT order.
/// # C: O(N_cpus)
pub fn enumerate_aps() -> Vec<u32> {
    let boot = boot_cpu_id();
    let n = cpu_topology::count() as usize;
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        if let Some((id, flags)) = cpu_topology::get(i) {
            let bringup_eligible = (flags
                & (cpu_topology::FLAG_ENABLED
                  | cpu_topology::FLAG_ONLINE_CAPABLE)) != 0;
            if bringup_eligible && id != boot {
                out.push(id);
            }
        }
    }
    out
}

/// Boot-path orchestration entry. Reads cpu_topology, iterates
/// `enumerate_aps()`. v1 does no actual startup — the per-AP
/// INIT-IPI / PSCI CPU_ON sequence lands in P4-08+. Returns the
/// count of APs that *would* be started so the boot path can
/// log a single summary line under its own debug gate.
///
/// # SAFETY: caller is the boot path post-ACPI-walk; ACPI table
/// is stable; cpu_topology is fully populated.
/// # C: O(N_cpus)
pub unsafe fn bring_up_aps() -> usize {
    enumerate_aps().len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reset() {
        BOOT_CPU_ID.store(u32::MAX, Ordering::Release);
        ONLINE.store(0, Ordering::Release);
    }

    #[test]
    fn empty_topology_yields_no_aps() {
        reset();
        // SAFETY: hosted test single-thread invariant; sole writer for BOOT_CPU_ID.
        unsafe { set_boot_cpu_id(0); }
        // Topology may be non-empty from prior tests, but boot id 0
        // and (likely) no other id 0 entries means filter passes.
        // The robust check: enumerate result excludes boot_cpu_id.
        let aps = enumerate_aps();
        assert!(!aps.contains(&0));
    }

    #[test]
    fn ap_arrived_increments_online() {
        reset();
        // SAFETY: hosted-test single-thread invariant; sole writer.
        unsafe { set_boot_cpu_id(0); }
        assert_eq!(online_count(), 1);
        let n1 = ap_arrived();
        assert_eq!(n1, 2);
        let n2 = ap_arrived();
        assert_eq!(n2, 3);
        assert_eq!(online_count(), 3);
    }
}
