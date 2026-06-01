// cgroup v2 cpu.max bandwidth scanner (`26`,`13§3`). Runs from the
// periodic kthread tick (NOT under the runqueue lock — freeze/unfreeze
// take that lock, so inline charging from update_curr would deadlock).
// Reuses the F319 freeze mechanism: a cgroup over its quota this period
// has every member frozen until the next period refill unthrottles it.
//
// Lives in the kernel crate because it bridges two leaf crates the
// cgroup crate can't depend on: `sched` (per-task sum_exec_runtime +
// freeze) and the cgroup tree.

#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::Ordering;

/// Cumulative CPU time consumed by every member of `pids` (sum of each
/// task's sum_exec_runtime_ns). Missing tasks contribute 0.
/// # C: O(members · registry-lookup)
fn members_runtime_ns(pids: &[u64]) -> u64 {
    let mut total = 0u64;
    for &p in pids {
        if let Some(t) = sched::live::registry::lookup_in_ns(0, p as u32) {
            total = total.saturating_add(t.sum_exec_runtime_ns.load(Ordering::Acquire));
        }
    }
    total
}

/// One scan pass: for every cgroup with a cpu.max quota, decide
/// throttle / continue / refill and apply it via the freezer. Called at
/// the coarse periodic cadence (same site as `tick_wake_expired`).
/// # C: O(quota-groups · members)
pub fn tick(now_ns: u64) {
    let groups = cgroup::cpu_quota_groups();
    for g in groups {
        let total = members_runtime_ns(&g.pids);
        match cgroup::cpu_bandwidth_decision(
            total, g.base_ns, g.quota_ns, g.period_ns, g.period_start_ns, now_ns,
        ) {
            cgroup::CpuAction::Continue => {}
            cgroup::CpuAction::Throttle => {
                if !g.throttled {
                    for &p in &g.pids {
                        if let Some(t) = sched::live::registry::lookup_in_ns(0, p as u32) {
                            sched::live::freeze_task(&t);
                        }
                    }
                    // base + period_start unchanged; only the flag flips.
                    cgroup::set_cpu_state(g.cgid, true, g.base_ns, g.period_start_ns);
                }
            }
            cgroup::CpuAction::Refill { new_base_ns } => {
                if g.throttled {
                    for &p in &g.pids {
                        if let Some(t) = sched::live::registry::lookup_in_ns(0, p as u32) {
                            sched::live::unfreeze_task(&t);
                        }
                    }
                }
                cgroup::set_cpu_state(g.cgid, false, new_base_ns, now_ns);
            }
        }
    }
}
