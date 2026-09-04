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
/// CPUs counted by the deadline admission domain. CPU-down removes this set
/// before ACTIVE, while ONLINE continues to name a reachable executing CPU.
static CAPACITY_MASK: crate::AtomicCpuMask = crate::AtomicCpuMask::new();
/// Scheduler placement eligibility, distinct from admission capacity.
/// CPU-down removes capacity first, then clears this set before waiting for
/// pre-existing placement readers.
static ACTIVE_MASK: crate::AtomicCpuMask = crate::AtomicCpuMask::new();
/// CPUs accepting new generic cross-call descriptors. This remains set after
/// ACTIVE clears, so TLB/membarrier still reach an executing deactivated CPU,
/// and clears only at the final stop boundary before ONLINE.
static CALLABLE_MASK: crate::AtomicCpuMask = crate::AtomicCpuMask::new();
const NO_HOTPLUG_OWNER: u32 = u32::MAX;
/// Linux `cpu_hotplug_lock` equivalent: one CPU-down writer owns topology
/// mutation, IRQ evacuation, and terminal publication at a time.
static HOTPLUG_OWNER: AtomicU32 = AtomicU32::new(NO_HOTPLUG_OWNER);

const HP_IDLE: u8 = 0;
const HP_REQUESTED: u8 = 1;
const HP_TAIL: u8 = 2;
const HP_FAILED: u8 = 3;
const HP_OFFLINE: u8 = 4;
const HP_COMMITTING: u8 = 5;
static HOTPLUG: [AtomicU8; crate::MAX_CPUS] = [const { AtomicU8::new(HP_IDLE) }; crate::MAX_CPUS];
static FROZEN: crate::AtomicCpuMask = crate::AtomicCpuMask::new();

/// Complete online CPU set encoded at the architecture transport width. This
/// is for generic infrastructure that cannot depend on the scheduler's CPU
/// mask type; scheduler consumers use [`online_cpumask`] directly.
/// # C: O(words)
pub fn online_transport_mask() -> [u64; hal::MAX_CPUS.div_ceil(u64::BITS as usize)] {
    let source = ONLINE_MASK.load(Ordering::Acquire);
    let mut out = [0u64; hal::MAX_CPUS.div_ceil(u64::BITS as usize)];
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

/// CPUs counted by scheduler admission capacity. # C: O(words)
pub fn capacity_cpumask() -> crate::CpuMask { CAPACITY_MASK.load(Ordering::Acquire) }

/// Compatibility spelling for physical cross-call reachability. # C: O(words)
pub fn live_cpumask() -> crate::CpuMask { online_cpumask() }

/// CPUs eligible for new scheduler placement. # C: O(words)
pub fn active_cpumask() -> crate::CpuMask { ACTIVE_MASK.load(Ordering::Acquire) }

/// CPUs accepting new call-function publication. # C: O(words)
pub fn callable_cpumask() -> crate::CpuMask { CALLABLE_MASK.load(Ordering::Acquire) }

/// Whether `cpu` may receive newly placed scheduler work. # C: O(1)
pub fn is_active(cpu: u32) -> bool {
    (cpu as usize) < crate::MAX_CPUS && ACTIVE_MASK.load(Ordering::Acquire).contains(cpu as usize)
}

/// RCU placement read section. A successful result remains valid through a
/// destination commit performed before this guard drops: CPU-down clears the
/// active bit and waits a grace period before evacuation. # C: O(1)
pub fn placement_guard(cpu: u32) -> Option<sync::RcuReadGuard> {
    let guard = sync::rcu_read_lock();
    if is_active(cpu) { Some(guard) } else { None }
}

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
        let _ = CAPACITY_MASK.set(cpu as usize, Ordering::Release);
        let _ = ACTIVE_MASK.set(cpu as usize, Ordering::Release);
        let _ = CALLABLE_MASK.set(cpu as usize, Ordering::Release);
    }
}

/// Remove this logical CPU from scheduler capacity while retaining transport
/// reachability for placement grace and evacuation.
/// # SAFETY: caller owns the serialized deadline-capacity transition.
/// # C: O(1)
pub unsafe fn mark_offline(cpu: u32) -> bool {
    if (cpu as usize) >= crate::MAX_CPUS { return false; }
    CAPACITY_MASK.clear_cpu(cpu as usize, Ordering::AcqRel)
}

/// Claim one serialized CPU-down transition. Capacity and active placement
/// remain unchanged until their owning stages run. # C: O(1)
pub fn request_offline(cpu: u32) -> bool {
    let Some(state) = HOTPLUG.get(cpu as usize) else { return false; };
    if HOTPLUG_OWNER.compare_exchange(NO_HOTPLUG_OWNER, cpu,
        Ordering::AcqRel, Ordering::Acquire).is_err() { return false; }
    let accepted = boot_logical_id() != Some(cpu) && active_cpumask().count_ones() > 1
        && online_cpumask().contains(cpu as usize) && is_active(cpu)
        && state.compare_exchange(HP_IDLE, HP_REQUESTED,
            Ordering::AcqRel, Ordering::Acquire).is_ok();
    if !accepted {
        let _ = HOTPLUG_OWNER.compare_exchange(cpu, NO_HOTPLUG_OWNER,
            Ordering::AcqRel, Ordering::Acquire);
    }
    accepted
}

/// Close new scheduler placement after deadline capacity was removed, then
/// wait out every selector that sampled the old active set. # Sleeps: y
/// # C: O(grace)
pub fn deactivate(cpu: u32) -> bool {
    deactivate_with(cpu, sync::synchronize_rcu)
}

fn deactivate_with<F>(cpu: u32, grace: F) -> bool
where F: FnOnce() {
    let Some(state) = HOTPLUG.get(cpu as usize) else { return false; };
    if state.load(Ordering::Acquire) != HP_REQUESTED
        || capacity_cpumask().contains(cpu as usize) { return false; }
    if !ACTIVE_MASK.clear_cpu(cpu as usize, Ordering::AcqRel) {
        return false;
    }
    grace();
    true
}

/// Compatibility spelling for scheduler placement eligibility. # C: O(1)
pub fn accepts_work(cpu: u32) -> bool {
    is_active(cpu)
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

/// Linearize final play-dead against coordinator cancellation. Once this
/// succeeds cancellation waits for the target's offline publication; if
/// cancellation wins first, the target must remain online. # C: O(1)
pub fn claim_offline_commit(cpu: u32) -> bool {
    HOTPLUG.get(cpu as usize).is_some_and(|s| s.compare_exchange(
        HP_TAIL, HP_COMMITTING, Ordering::AcqRel, Ordering::Acquire).is_ok())
}

/// Publish target-side refusal before returning from the call handler. # C: O(1)
pub fn reject_offline(cpu: u32) {
    let Some(state) = HOTPLUG.get(cpu as usize) else { return; };
    loop {
        let observed = state.load(Ordering::Acquire);
        if observed == HP_IDLE || observed == HP_COMMITTING || observed == HP_OFFLINE { return; }
        if !matches!(observed, HP_REQUESTED | HP_TAIL | HP_FAILED) { return; }
        if observed != HP_FAILED && state.compare_exchange(observed, HP_FAILED,
            Ordering::AcqRel, Ordering::Acquire).is_err() { continue; }
        if online_cpumask().contains(cpu as usize) {
            let _ = CAPACITY_MASK.set(cpu as usize, Ordering::Release);
            let _ = ACTIVE_MASK.set(cpu as usize, Ordering::Release);
            let _ = CALLABLE_MASK.set(cpu as usize, Ordering::Release);
        }
        return;
    }
}

/// Restore hardware and then software topology after a CPU_OFF primitive
/// returns. The callback runs while every admission mask remains closed, so
/// ACTIVE never advertises a CPU unable to receive interrupts or timer work.
/// # SAFETY: caller is the refused target CPU and owns its lifecycle state.
pub unsafe fn restore_offline_refusal_with<F>(cpu: u32, restore_local: F)
where F: FnOnce() {
    let Some(state) = HOTPLUG.get(cpu as usize) else { return; };
    if !matches!(state.load(Ordering::Acquire), HP_COMMITTING | HP_OFFLINE) { return; }
    restore_local();
    // SAFETY: the target is still physically executing after refusal.
    unsafe { mark_online(cpu); }
    let _ = FROZEN.clear_cpu(cpu as usize, Ordering::AcqRel);
    state.store(HP_FAILED, Ordering::Release);
}

/// Close generic cross-call publication from the process-context coordinator
/// after scheduler evacuation. Existing readers may publish during the grace;
/// the later terminal IPI drains them before its final locked proof.
/// Cancellation can win during the grace and re-open CALLABLE.
/// # Sleeps: y # Ctx: process # C: O(grace)
pub fn begin_callfn_shutdown(cpu: u32) -> bool {
    begin_callfn_shutdown_with(cpu, sync::synchronize_rcu)
}

fn begin_callfn_shutdown_with<F>(cpu: u32, grace: F) -> bool
where F: FnOnce() {
    let Some(state) = HOTPLUG.get(cpu as usize) else { return false; };
    if !matches!(state.load(Ordering::Acquire), HP_REQUESTED | HP_TAIL) { return false; }
    if CALLABLE_MASK.clear_cpu(cpu as usize, Ordering::AcqRel) { grace(); }
    matches!(state.load(Ordering::Acquire), HP_REQUESTED | HP_TAIL)
        && !callable_cpumask().contains(cpu as usize)
}

/// Publish that `cpu` has left the online set and is entering architecture
/// play-dead. The frozen set records only successful transitions. # C: O(1)
pub fn finish_offline(cpu: u32) {
    let _ = ACTIVE_MASK.clear_cpu(cpu as usize, Ordering::AcqRel);
    let _ = CAPACITY_MASK.clear_cpu(cpu as usize, Ordering::AcqRel);
    let _ = CALLABLE_MASK.clear_cpu(cpu as usize, Ordering::AcqRel);
    if ONLINE_MASK.clear_cpu(cpu as usize, Ordering::AcqRel) {
        ONLINE.fetch_sub(1, Ordering::AcqRel);
    }
    let _ = FROZEN.set(cpu as usize, Ordering::AcqRel);
    if let Some(s) = HOTPLUG.get(cpu as usize) { s.store(HP_OFFLINE, Ordering::Release); }
    let _ = HOTPLUG_OWNER.compare_exchange(cpu, NO_HOTPLUG_OWNER,
        Ordering::AcqRel, Ordering::Acquire);
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
    let Some(state) = HOTPLUG.get(cpu as usize) else { return; };
    loop {
        match state.load(Ordering::Acquire) {
            HP_REQUESTED | HP_TAIL | HP_FAILED => {
                let observed = state.load(Ordering::Acquire);
                if !matches!(observed, HP_REQUESTED | HP_TAIL | HP_FAILED) { continue; }
                if state.compare_exchange(observed, HP_IDLE, Ordering::AcqRel,
                    Ordering::Acquire).is_err() { continue; }
                let _ = FROZEN.clear_cpu(cpu as usize, Ordering::AcqRel);
                let _ = CAPACITY_MASK.set(cpu as usize, Ordering::Release);
                let _ = ACTIVE_MASK.set(cpu as usize, Ordering::Release);
                let _ = CALLABLE_MASK.set(cpu as usize, Ordering::Release);
                let _ = HOTPLUG_OWNER.compare_exchange(cpu, NO_HOTPLUG_OWNER,
                    Ordering::AcqRel, Ordering::Acquire);
                return;
            }
            HP_COMMITTING => sync::spin_relax::relax(),
            HP_IDLE | HP_OFFLINE => return,
            _ => return,
        }
    }
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
        let _ = ACTIVE_MASK.set(cpu as usize, Ordering::Release);
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
/// Canonical dense scheduler ID resolved once beside [`BOOT_CPU_ID`]. The
/// topology may use sparse APIC IDs/MPIDRs, so no later path may reinterpret
/// the hardware ID as a logical index.
static BOOT_LOGICAL_ID: AtomicU32 = AtomicU32::new(u32::MAX);

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
    BOOT_LOGICAL_ID.store(boot_logical, Ordering::Release);
    // SAFETY: boot path, sole writer for the boot CPU's bit.
    unsafe { mark_online(boot_logical); }
}

/// Boot CPU's APIC id / MPIDR. `u32::MAX` if `set_boot_cpu_id`
/// hasn't run yet.
/// # C: O(1)
pub fn boot_cpu_id() -> u64 { BOOT_CPU_ID.load(Ordering::Acquire) }

/// Dense logical ID permanently paired with the boot hardware ID. # C: O(1)
pub fn boot_logical_id() -> Option<u32> {
    let id = BOOT_LOGICAL_ID.load(Ordering::Acquire);
    ((id as usize) < crate::MAX_CPUS).then_some(id)
}

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
#[path = "smp/tests.rs"]
mod tests;
