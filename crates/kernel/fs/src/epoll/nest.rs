// `ep_loop_check` — the graph walk behind `epoll_ctl(EPOLL_CTL_ADD)`'s ELOOP.
//
// Two independent measurements share one budget: how far the tree BELOW the
// epoll being added reaches, and how far the epolls watching the DESTINATION
// reach above it. Measuring only one direction admits a chain the other end
// can already have built, so the pure verdict lives in `super::policy` and
// this file owns only the two walks that feed it.

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::policy::{nesting_admits, EP_MAX_NESTS};
use super::{epoll_inode_of, epolls_snapshot, EpollData};

/// Walk down from `start`, returning the subtree depth, or `None` when the
/// walk reaches `needle` (a cycle) or runs past the nesting budget.
/// # C: O(N_epoll_graph)
fn downward_depth(start: &Arc<EpollData>, needle: u32, depth: usize) -> Option<usize> {
    if start.id == needle { return None; }
    if depth > EP_MAX_NESTS { return None; }
    let entries = start.entries.lock().clone();
    let mut result = 0usize;
    for item in entries {
        let Some(file) = item.file.upgrade() else { continue; };
        let Some(child) = epoll_inode_of(&file) else { continue; };
        let below = downward_depth(&child, needle, depth + 1)?;
        result = result.max(below + 1);
        if result > EP_MAX_NESTS { return None; }
    }
    Some(result)
}

/// Walk up from `target`, returning how deep the chain of epolls that watch it
/// reaches. Bounded by the same budget so a pre-existing over-long chain
/// cannot make the walk unbounded. # C: O(N_epoll_graph)
fn upward_depth(target_id: u32, depth: usize, seen: &mut Vec<u32>) -> usize {
    if depth > EP_MAX_NESTS || seen.contains(&target_id) { return 0; }
    seen.push(target_id);
    let mut result = 0usize;
    for ep in epolls_snapshot() {
        if ep.id == target_id { continue; }
        let watches_target = ep.entries.lock().iter().any(|item| {
            item.file.upgrade()
                .and_then(|f| epoll_inode_of(&f))
                .is_some_and(|child| child.id == target_id)
        });
        if watches_target {
            result = result.max(upward_depth(ep.id, depth + 1, seen) + 1);
        }
    }
    result
}

/// `ep_loop_check(ep, to)`: may `to` be added to `ep`? False for a cycle and
/// for a chain longer than the nesting budget in either direction.
/// # C: O(N_epoll_graph)
pub(super) fn loop_check(ep: &Arc<EpollData>, to: &Arc<EpollData>) -> bool {
    let Some(down) = downward_depth(to, ep.id, 0) else { return false; };
    let up = upward_depth(ep.id, 0, &mut Vec::new());
    nesting_admits(down, up)
}
