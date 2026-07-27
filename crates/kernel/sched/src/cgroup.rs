// cgroup v2 cpu.max bandwidth scanner (`26`,`13§3`). Runs from the
// periodic kthread tick (NOT under the runqueue lock — freeze/unfreeze
// take that lock, so inline charging from update_curr would deadlock).
// Reuses the F319 freeze mechanism: a cgroup over its quota this period
// has every member frozen until the next period refill unthrottles it.
//
// The cpu cgroup controller (CFS bandwidth) lives in `sched` — the
// scheduler owns cpu.max enforcement, reading quota groups from the leaf
// `cgroup` crate (sched->cgroup, no cycle). Linux: kernel/sched cfs_bandwidth.


use core::sync::atomic::Ordering;

fn lookup_init_pid(pid: u32) -> Option<alloc::sync::Arc<crate::Task>> {
    let namespace = namespace_identity::initial(namespace_identity::NamespaceKind::Pid);
    crate::registry::lookup_in_namespace(&namespace, pid)
}

/// Cumulative CPU time consumed by every member of `pids` (sum of each
/// task's sum_exec_runtime_ns). Missing tasks contribute 0.
/// # C: O(members · registry-lookup)
fn members_runtime_ns(pids: &[u64]) -> u64 {
    let mut total = 0u64;
    for &p in pids {
        if let Some(t) = lookup_init_pid(p as u32) {
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
                        if let Some(t) = lookup_init_pid(p as u32) {
                            crate::live::freeze_task(&t);
                        }
                    }
                    // base + period_start unchanged; only the flag flips.
                    cgroup::set_cpu_state(g.cgid, true, g.base_ns, g.period_start_ns);
                }
            }
            cgroup::CpuAction::Refill { new_base_ns } => {
                if g.throttled {
                    for &p in &g.pids {
                        if let Some(t) = lookup_init_pid(p as u32) {
                            crate::live::unfreeze_task(&t);
                        }
                    }
                }
                cgroup::set_cpu_state(g.cgid, false, new_base_ns, now_ns);
            }
        }
    }
}

// ---- cgroup controllers that manipulate task scheduling state ----
// freezer / cpuset / cpu.weight / cgroup.kill / pid-resolve. Linux keeps
// these in the scheduler (kernel/sched, kernel/cgroup/freezer); they read
// the leaf `cgroup` crate's hierarchy and act on tasks via the runqueue.
use core::sync::atomic::Ordering as CgOrd;

/// cgroup.kill: post `sig` to the global-tid `pid` task and wake it.
/// # C: O(N) registry lookup
pub fn kill_hook(pid: u64, sig: i32) {
    if !(1..=64).contains(&sig) { return; }
    if let Some(t) = lookup_init_pid(pid as u32) {
        t.sigpending.fetch_or(1u64 << (sig - 1), CgOrd::Release);
        crate::live::signal_wake_up(&t);
    }
}

/// cgroup.freeze: freeze (`v`) / thaw the global-tid `pid` task.
/// # C: O(N) registry lookup + runqueue op
pub fn freeze_hook(pid: u64, v: bool) {
    if let Some(t) = lookup_init_pid(pid as u32) {
        if v { crate::live::freeze_task(&t); } else { crate::live::unfreeze_task(&t); }
    }
}

/// cpuset.cpus: narrow the task's CPU set. Linux keeps the cpuset and the
/// `sched_setaffinity(2)` request in separate fields (`cpuset_cpus_allowed` vs
/// `user_cpus_ptr`) and derives `cpus_mask` from both, so neither erases the
/// other; storing the cpuset straight into the effective mask would make the
/// two a last-writer-wins pair. An empty intersection leaves the cpuset in
/// force rather than parking the task on an unschedulable mask.
/// # C: O(N) registry lookup + O(N_cpus) relocate
pub fn cpuset_hook(pid: u64, mask: u64) {
    if mask == 0 { return; }
    if let Some(t) = lookup_init_pid(pid as u32) {
        t.cpuset_cpus_allowed.store(mask, CgOrd::Release);
        let user = t.user_cpus_allowed.load(CgOrd::Acquire);
        let eff = crate::affinity::compose(mask, user);
        t.cpus_allowed.store(eff, CgOrd::Release);
        crate::live::relocate_for_affinity(&t, eff);
    }
}

/// cpu.weight: set the live CFS load weight of the global-tid `pid` task.
/// # C: O(N) registry lookup
pub fn weight_hook(pid: u64, weight: u32) {
    if let Some(t) = lookup_init_pid(pid as u32) {
        t.load_weight.store(weight, CgOrd::Release);
    }
}

/// vpid → global tid for cgroup.procs/threads writes (identity fallback).
/// # C: O(N) registry lookup
pub fn pid_resolve_hook(vpid: u64) -> Option<u64> {
    crate::live::registry::lookup_by_vpid(vpid as u32).map(|t| t.tid as u64)
}

/// global tid → visible pid for cgroup.procs/threads reads.
/// # C: O(N) registry lookup
pub fn pid_display_hook(tid: u64) -> u64 {
    crate::live::registry::display_vpid(tid as u32)
}

/// Register the scheduler's cgroup controllers with the cgroup crate.
/// Called once at boot.
/// # C: O(1)
pub fn install() {
    cgroup::set_signal_hook(kill_hook);
    cgroup::set_freeze_hook(freeze_hook);
    cgroup::set_weight_hook(weight_hook);
    cgroup::set_cpuset_hook(cpuset_hook);
    cgroup::set_pid_resolve_hook(pid_resolve_hook);
    cgroup::set_pid_display_hook(pid_display_hook);
}
