//! Mount propagation (`docs/16§6`, `mount_namespaces(7)`): peer-group event
//! delivery + slave fan-out. Split out of `mount.rs` to hold the line cap; all
//! parent state reached via `use super::*`. PURE MOVE — no behavior change.

use super::*;

/// Collect propagation targets for a mount created under `parent`: every peer
/// of `parent`'s peer group, plus the transitive slaves of `parent` and those
/// peers (Linux `propagate_mnt`: events flow to peers and down to slaves, but
/// a slave never propagates back to its master). Linux gates this on
/// `IS_MNT_SHARED(dest)` (`attach_recursive_mnt`/`propagate_umount`): an event
/// originates ONLY when `parent` is itself SHARED. A pure SLAVE receives from
/// its master but never SENDS; PRIVATE/UNBINDABLE drop all propagation. Empty
/// otherwise — this also defends a former master demoted to slave/private whose
/// stale `mnt_slave_list` must no longer receive its events. # C: O(N_mounts)
pub(super) fn propagation_targets(parent: &Arc<Mount>) -> Vec<Arc<Mount>> {
    let ns = parent.ns;
    // IS_MNT_SHARED(dest) gate: only a SHARED parent originates propagation.
    if Propagation::from_u8(parent.propagation.load(Ordering::Acquire)) != Propagation::Shared {
        return Vec::new();
    }
    let pg = parent.peer_group.load(Ordering::Acquire);
    let mut out: Vec<Arc<Mount>> = Vec::new();
    let mut seen: Vec<u64> = alloc::vec![parent.mnt_id];
    // Peers: shared mounts in the same group (excluding parent).
    if pg != 0 {
        for m in mounts_in_ns(ns) {
            if m.mnt_id == parent.mnt_id { continue; }
            if Propagation::from_u8(m.propagation.load(Ordering::Acquire)) == Propagation::Shared
                && m.peer_group.load(Ordering::Acquire) == pg {
                seen.push(m.mnt_id); out.push(m);
            }
        }
    }
    // Transitive slaves of {parent} ∪ peers, restricted to the same ns (a
    // cross-ns slave clone receives via its own ns's machinery, not here).
    let mut frontier: Vec<Arc<Mount>> = alloc::vec![parent.clone()];
    frontier.extend(out.iter().cloned());
    while let Some(m) = frontier.pop() {
        for w in m.mnt_slave_list.lock().iter() {
            if let Some(s) = w.upgrade() {
                if s.ns != ns || seen.contains(&s.mnt_id) { continue; }
                seen.push(s.mnt_id);
                frontier.push(s.clone());
                out.push(s);
            }
        }
    }
    out
}

/// Propagation event delivery (`docs/16§6`): replicate the mount just created
/// at dentry `at` to every propagation target of its PARENT mount. Returns the
/// count propagated. # C: O(N_mounts × depth)
pub fn propagate_mount(at: &Arc<Dentry>) -> usize {
    let ns = current_ns();
    let newm = match mount_exact_at(ns, at) { Some(m) => m, None => return 0 };
    let parent = match mount_by_id(newm.parent_id.load(Ordering::Acquire)) {
        Some(p) => p, None => return 0,
    };
    let targets = propagation_targets(&parent);
    if targets.is_empty() { return 0; }
    let new_mp = match newm.mountpoint() { Some(d) => d, None => return 0 };
    let rel = match rel_under(&new_mp, parent.mountpoint().as_ref()) {
        Some(r) if !r.is_empty() => r, _ => return 0,
    };
    let root = match newm.root.clone().or_else(|| newm.fs().root()) {
        Some(r) => r, None => return 0,
    };
    let mut n = 0;
    for peer in targets {
        if peer.ns != ns { continue; }
        let base = match peer.mountpoint().or_else(global_root) { Some(b) => b, None => continue };
        let Some(dst) = descend(&base, &rel) else { continue; };
        if register_bind(Some(dst), newm.fs().clone(), root.clone()).is_ok() { n += 1; }
    }
    n
}

/// Peer group id of the mount rooted exactly at dentry `d`, or 0. # C: O(log N)
pub fn peer_group_of(d: &Arc<Dentry>) -> u64 {
    mount_exact_at(current_ns(), d)
        .map(|m| m.peer_group.load(Ordering::Acquire)).unwrap_or(0)
}

/// MS_SHARED peer-group inheritance (`docs/16§6`). # C: O(log N)
pub fn join_peer_group(d: &Arc<Dentry>, pg: u64) {
    if pg == 0 { return; }
    if let Some(m) = mount_exact_at(current_ns(), d) {
        m.peer_group.store(pg, Ordering::Release);
        m.propagation.store(Propagation::Shared as u8, Ordering::Release);
        crate::mntns::bump_gen(m.ns);
    }
}
