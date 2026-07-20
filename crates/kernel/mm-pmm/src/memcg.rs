//! PMM-owned memcg pressure transactions.

use cgroup::{MemoryPressure, MemoryPressureResult};

/// Execute a pressure transition after cgroup released its hierarchy lock.
/// High pressure synchronously reclaims one charged inactive-anon page before
/// allowing the allocating task to continue, which is the throttle boundary.
/// A hard max retries only after that exact cgroup released a page; otherwise
/// the scheduler selects and SIGKILLs a victim in the limiting subtree.
/// # C: O(one memcg LRU transaction + O(members) on OOM)
fn pressure(cgid: u64, pressure: MemoryPressure) -> MemoryPressureResult {
    match pressure {
        MemoryPressure::High => {
            let _ = crate::user_as::pageout::reclaim_one_anon_page_memcg(cgid);
            MemoryPressureResult::Continue
        }
        MemoryPressure::Max { limit_cgid } => {
            if crate::user_as::pageout::reclaim_one_anon_page_memcg(cgid) {
                MemoryPressureResult::Retry
            } else {
                let _ = sched::oom::kill_memcg(limit_cgid);
                MemoryPressureResult::Continue
            }
        }
    }
}

/// Install PMM reclaim and scheduler OOM as the only cgroup pressure owner.
/// # C: O(1)
pub fn install_memcg_pressure_policy() { cgroup::set_memory_pressure_hook(pressure); }
