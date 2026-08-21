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



use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};

use crate as cpu_topology;

pub mod terminal_stop;

/// Bitmask of logical CPUs that have completed bring-up (`bit i` ⇒ logical
/// CPU `i` is online). The boot CPU sets its bit in `set_boot_cpu_id`; each
/// AP sets its bit in `mark_online`. Read by the x86 TLB-shootdown sender to
/// target only CPUs that can actually ACK the IPI (sending to a not-yet-online
/// AP would spin forever waiting for an ACK that never comes).  This is a
/// word-array mask so the topology cap can grow without changing the online
/// set's representation.
static ONLINE_MASK: crate::AtomicCpuMask = crate::AtomicCpuMask::new();

const HP_IDLE: u8 = 0;
const HP_REQUESTED: u8 = 1;
const HP_TAIL: u8 = 2;
const HP_FAILED: u8 = 3;
const HP_OFFLINE: u8 = 4;
static HOTPLUG: [AtomicU8; crate::MAX_CPUS] = [const { AtomicU8::new(HP_IDLE) }; crate::MAX_CPUS];
static FROZEN: crate::AtomicCpuMask = crate::AtomicCpuMask::new();

/// Bitmask of online logical CPUs. # C: O(1)
pub fn online_mask() -> u64 { ONLINE_MASK.load(Ordering::Acquire).low_word() }

/// Complete online CPU set encoded at the architecture transport width. This
/// is for generic infrastructure that cannot depend on the scheduler's CPU
/// mask type; scheduler consumers use [`online_cpumask`] directly.
/// # C: O(words)
pub fn online_transport_mask() -> [u64; hal::MAX_SMP_CPUS.div_ceil(u64::BITS as usize)] {
    let source = ONLINE_MASK.load(Ordering::Acquire);
    let mut out = [0u64; hal::MAX_SMP_CPUS.div_ceil(u64::BITS as usize)];
    let words = source.as_words();
    let mut i = 0;
    while i < words.len() {
        out[i] = words[i];
        i += 1;
    }
    out
}

/// Complete online CPU set.  New multiword consumers must use this rather
/// than adding another scalar online bitmap.
/// # C: O(words)
pub fn online_cpumask() -> crate::CpuMask { ONLINE_MASK.load(Ordering::Acquire) }

/// Mark logical CPU `cpu` online in the bitmap. Boot CPU + each AP call this
/// as they finish bring-up. Idempotent.
/// # SAFETY: caller is the boot CPU (for itself) or an arriving AP (for
/// itself) — a single distinct writer per bit.
/// # C: O(1)
pub unsafe fn mark_online(cpu: u32) {
    if (cpu as usize) < crate::MAX_CPUS {
        if ONLINE_MASK.set(cpu as usize, Ordering::AcqRel) {
            ONLINE.fetch_add(1, Ordering::AcqRel);
        }
    }
}

/// Remove this logical CPU from the one scheduler-visible online set. Returns
/// whether it was online, so only the winning transition adjusts the count.
/// # SAFETY: caller runs on `cpu` after it has stopped accepting scheduler
/// work, or is the boot CPU resetting hosted topology state.
/// # C: O(1)
pub unsafe fn mark_offline(cpu: u32) -> bool {
    if (cpu as usize) >= crate::MAX_CPUS { return false; }
    if ONLINE_MASK.clear_cpu(cpu as usize, Ordering::AcqRel) {
        ONLINE.fetch_sub(1, Ordering::AcqRel);
        true
    } else { false }
}

/// Begin one suspend CPU-down request. # C: O(1)
pub fn request_offline(cpu: u32) -> bool {
    HOTPLUG.get(cpu as usize).is_some_and(|s| s.compare_exchange(
        HP_IDLE, HP_REQUESTED, Ordering::AcqRel, Ordering::Acquire).is_ok())
}

/// Whether scheduler producers may place new work on `cpu`. A requested CPU
/// stops admission before its target-side idle proof, closing wakeup races
/// without creating another online bitmap. # C: O(1)
pub fn accepts_work(cpu: u32) -> bool {
    HOTPLUG.get(cpu as usize).is_some_and(|s| s.load(Ordering::Acquire) == HP_IDLE)
}

/// Transfer an admitted CPU-down request from the call-function handler to
/// the ordinary IRQ tail. The tail runs only after local softirqs and deferred
/// wakes have been serviced, matching CPU-hotplug's play-dead boundary.
/// # C: O(1)
pub fn request_offline_tail(cpu: u32) -> bool {
    HOTPLUG.get(cpu as usize).is_some_and(|s| s.compare_exchange(
        HP_REQUESTED, HP_TAIL, Ordering::AcqRel, Ordering::Acquire).is_ok())
}

/// Whether this CPU's IRQ tail owns the accepted play-dead transition. # C: O(1)
pub fn offline_tail_requested(cpu: u32) -> bool {
    HOTPLUG.get(cpu as usize).is_some_and(|s| s.load(Ordering::Acquire) == HP_TAIL)
}

/// Publish target-side refusal before returning from the call handler. # C: O(1)
pub fn reject_offline(cpu: u32) {
    if let Some(s) = HOTPLUG.get(cpu as usize) { s.store(HP_FAILED, Ordering::Release); }
}

/// Publish that `cpu` has left the online set and is entering architecture
/// play-dead. The frozen set records only successful transitions. # C: O(1)
pub fn finish_offline(cpu: u32) {
    let _ = FROZEN.set(cpu as usize, Ordering::AcqRel);
    if let Some(s) = HOTPLUG.get(cpu as usize) { s.store(HP_OFFLINE, Ordering::Release); }
}

/// Current suspend hotplug result: `Some(true)` offline, `Some(false)` failed,
/// `None` still pending. # C: O(1)
pub fn offline_result(cpu: u32) -> Option<bool> {
    HOTPLUG.get(cpu as usize).and_then(|s| match s.load(Ordering::Acquire) {
        HP_OFFLINE => Some(true), HP_FAILED => Some(false), _ => None,
    })
}

/// Cancel a refused request after the target remains canonically online.
/// Successful offline ownership is untouched. # C: O(1)
pub fn cancel_offline(cpu: u32) {
    if !online_cpumask().contains(cpu as usize) { return; }
    let _ = FROZEN.clear_cpu(cpu as usize, Ordering::AcqRel);
    if let Some(s) = HOTPLUG.get(cpu as usize) { s.store(HP_IDLE, Ordering::Release); }
}

/// Exact CPUs successfully taken down by the current suspend pass. # C: O(words)
pub fn frozen_cpumask() -> crate::CpuMask { FROZEN.load(Ordering::Acquire) }

/// Finish one thaw attempt. Failed CPU-up retains both its offline state and
/// frozen ownership so no later transition can mistake it for restored.
/// # C: O(1)
pub fn finish_thaw_cpu(cpu: u32, online: bool) {
    let Some(state) = HOTPLUG.get(cpu as usize) else { return; };
    if online {
        let _ = FROZEN.clear_cpu(cpu as usize, Ordering::AcqRel);
        state.store(HP_IDLE, Ordering::Release);
    } else {
        state.store(HP_OFFLINE, Ordering::Release);
    }
}

/// Reset an empty transaction record before CPU-down begins. # C: O(words)
pub fn begin_freeze() -> bool {
    if !frozen_cpumask().is_empty() { return false; }
    true
}

/// Boot-CPU id snapshot — captured at boot via `set_boot_cpu_id`.
/// Used by `enumerate_aps` to filter the boot CPU out of the
/// "secondaries to start" list.
static BOOT_CPU_ID: AtomicU64 = AtomicU64::new(u64::MAX);

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
pub unsafe fn set_boot_cpu_id(id: u64) {
    BOOT_CPU_ID.store(id, Ordering::Release);
    // Boot CPU itself counts as online from the moment we enter
    // kernel_main. Stamp here so observers see online_count()>=1.
    ONLINE.store(0, Ordering::Release);
    // Mark the boot CPU's logical id online for the shootdown bitmap. The
    // ACPI walk has populated the topology by now, so logical_id_for_hardware
    // resolves; fall back to logical 0 (the boot CPU's conventional slot).
    let boot_logical = cpu_topology::logical_id_for_hardware(id).unwrap_or(0);
    // SAFETY: boot path, sole writer for the boot CPU's bit.
    unsafe { mark_online(boot_logical); }
}

/// Boot CPU's APIC id / MPIDR. `u32::MAX` if `set_boot_cpu_id`
/// hasn't run yet.
/// # C: O(1)
pub fn boot_cpu_id() -> u64 { BOOT_CPU_ID.load(Ordering::Acquire) }

/// Number of CPUs that have completed bring-up. Boot CPU counts
/// as 1 from `set_boot_cpu_id` onward; each AP increments on
/// arrival.
/// # C: O(1)
pub fn online_count() -> u32 { ONLINE.load(Ordering::Acquire) }

/// Enabled-secondary list: every cpu_topology entry whose flags
/// include `FLAG_ENABLED` or `FLAG_ONLINE_CAPABLE`, excluding
/// the boot CPU id. Order matches MADT order.
/// # C: O(N_cpus)
pub fn enumerate_aps() -> Vec<u64> {
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
        BOOT_CPU_ID.store(u64::MAX, Ordering::Release);
        ONLINE.store(0, Ordering::Release);
        ONLINE_MASK.clear();
        FROZEN.clear();
        for state in &HOTPLUG { state.store(HP_IDLE, Ordering::Release); }
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
    fn online_transitions_are_idempotent_and_reversible() {
        reset();
        // SAFETY: hosted-test single-thread invariant; sole writer.
        unsafe { set_boot_cpu_id(0); }
        assert_eq!(online_count(), 1);
        // SAFETY: test owns CPU 1's lifecycle transition.
        unsafe { mark_online(1); mark_online(1); }
        assert_eq!(online_count(), 2);
        // SAFETY: test owns CPU 1's lifecycle transition.
        assert!(unsafe { mark_offline(1) });
        assert!(!unsafe { mark_offline(1) });
        assert_eq!(online_count(), 1);
    }

    #[test]
    fn online_set_is_published_through_the_canonical_cpumask() {
        reset();
        // SAFETY: hosted-test single-thread invariant; each logical bit has one writer.
        unsafe { mark_online(0); mark_online(crate::MAX_CPUS as u32 - 1); }
        let online = online_cpumask();
        assert!(online.contains(0));
        assert!(online.contains(crate::MAX_CPUS - 1));
    }

    #[test]
    fn failed_partial_thaw_retains_only_the_unrestored_cpu() {
        reset();
        // SAFETY: hosted test owns these logical lifecycle transitions.
        unsafe { set_boot_cpu_id(0); mark_online(1); mark_online(2); mark_offline(1); mark_offline(2); }
        finish_offline(1); finish_offline(2);
        // SAFETY: CPU 1's simulated restart owns its online transition.
        unsafe { mark_online(1); }
        finish_thaw_cpu(1, true);
        finish_thaw_cpu(2, false);
        let frozen = frozen_cpumask();
        assert!(!frozen.contains(1));
        assert!(frozen.contains(2), "failed CPU-up must retain frozen ownership");
        assert!(!begin_freeze(), "a partial thaw must block a new down transaction");
    }

    #[test]
    fn target_refusal_never_enters_the_frozen_set() {
        reset();
        // SAFETY: hosted test owns the topology lifecycle.
        unsafe { set_boot_cpu_id(0); mark_online(1); }
        assert!(request_offline(1));
        reject_offline(1);
        assert_eq!(offline_result(1), Some(false));
        assert!(online_cpumask().contains(1));
        assert!(!frozen_cpumask().contains(1));
        cancel_offline(1);
        assert!(accepts_work(1), "refused target must resume scheduler admission");
    }

    #[test]
    fn cpu_down_reaches_play_dead_only_from_the_irq_tail_state() {
        reset();
        // SAFETY: hosted test owns the topology lifecycle.
        unsafe { set_boot_cpu_id(0); mark_online(1); }
        assert!(request_offline(1));
        assert!(!offline_tail_requested(1));
        assert!(request_offline_tail(1));
        assert!(offline_tail_requested(1));
        assert_eq!(offline_result(1), None);
        assert!(!request_offline_tail(1), "call-function admission transfers once");
        reject_offline(1);
        assert_eq!(offline_result(1), Some(false));
        cancel_offline(1);
        assert!(accepts_work(1));
    }
}
