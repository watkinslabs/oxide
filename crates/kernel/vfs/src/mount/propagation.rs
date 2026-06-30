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

/// Assign the source new mount a peer group and mark it SHARED, returning the
/// group id (Linux `invent_group_ids` + `set_mnt_shared` over the propagated
/// source subtree). Reuses an existing group if the source already had one — a
/// fresh group otherwise, DISTINCT from the parent's so the new tree forms its
/// own peer group (`propagate_one` makes copies peers of the SOURCE, not of the
/// parent group). # C: O(1)
fn make_shared_group(m: &Arc<Mount>) -> u64 {
    let mut grp = m.peer_group.load(Ordering::Acquire);
    if grp == 0 {
        grp = super::NEXT_PEER_GROUP.fetch_add(1, Ordering::Relaxed);
        m.peer_group.store(grp, Ordering::Release);
    }
    m.propagation.store(Propagation::Shared as u8, Ordering::Release);
    grp
}

/// Propagation event delivery (`docs/16§6`): replicate the mount just created
/// at dentry `at` to every propagation target of its PARENT mount, mirroring
/// Linux `propagate_mnt`/`propagate_one`. The source mount and each PEER copy
/// join ONE new peer group (`CL_MAKE_SHARED`) so a later mount under any peer
/// propagates back; a copy landing on a SLAVE of the group becomes a SLAVE of
/// the source (`CL_SLAVE`) — it receives master events but never originates.
/// Returns the count propagated. # C: O(N_mounts × depth)
pub fn propagate_mount(at: &Arc<Dentry>) -> usize {
    let ns = current_ns();
    let newm = match mount_exact_at(ns, at) { Some(m) => m, None => return 0 };
    let parent = match mount_by_id(newm.parent_id.load(Ordering::Acquire)) {
        Some(p) => p, None => return 0,
    };
    let targets = propagation_targets(&parent);
    // Private/root parent (the common boot case) originates nothing — early-out
    // BEFORE any copy_tree clone (boot-safety).
    if targets.is_empty() { return 0; }
    let new_mp = match newm.mountpoint() { Some(d) => d, None => return 0 };
    // Position of the source under its parent — replicated at the same relative
    // position under each propagation target (peers/targets live at DISTINCT
    // dentries, so the Linux same-mountpoint-dentry shortcut does not apply in
    // this engine; `descend` re-materialises the slot per target).
    let rel = match rel_under(&new_mp, parent.mountpoint().as_ref()) {
        Some(r) if !r.is_empty() => r, _ => return 0,
    };
    // CL_MAKE_SHARED over the source: it and its peer copies form a NEW group.
    let parent_pg = parent.peer_group.load(Ordering::Acquire);
    let grp = make_shared_group(&newm);
    let mut n = 0;
    for peer in targets {
        if peer.ns != ns { continue; }
        let base = match peer.mountpoint().or_else(global_root) { Some(b) => b, None => continue };
        let Some(dst) = descend(&base, &rel) else { continue; };
        // A copy landing on a PEER of the parent group is itself shared in the
        // new group (CL_MAKE_SHARED); a copy on a SLAVE becomes a slave of the
        // source (CL_SLAVE) — receives master events, never originates.
        let is_peer = Propagation::from_u8(peer.propagation.load(Ordering::Acquire)) == Propagation::Shared
            && peer.peer_group.load(Ordering::Acquire) == parent_pg;
        let ty = if is_peer { CloneType::MakeShared } else { CloneType::Slave };
        // Clone the source subtree (freshly-created `newm` is childless at this
        // point, so this is one node) and splice it at `dst` under the target.
        let nodes = copy_tree(&newm, &new_mp, ty, grp, &newm, ns, true, None);
        // The peer copy's root lands at `dst` under this `peer` mount; `0` lets
        // `commit_tree` derive the (unambiguous, distinct-dentry) parent itself.
        n += commit_tree(nodes, &dst, 0, None, ns);
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

/// Linux `do_make_slave`: re-home `m` as a slave, TRANSFERRING its own slave
/// list to the inheriting master so no slave is left pointing at a mount that
/// is about to stop originating events. Master selection mirrors upstream:
///   * `m` shared WITH a surviving peer ⇒ master = a remaining peer in the
///     group (`m` slaves to the peer group it is leaving), and `m` drops its
///     own group id (`mnt_release_group_id` + `CLEAR_MNT_SHARED`);
///   * `m` not shared but already a slave ⇒ master = its existing master
///     (`m`'s sub-slaves rise one level to that master);
///   * neither ⇒ no master: `m`'s slaves are ORPHANED (master cleared) and `m`
///     is left masterless.
/// On return `m` is `Slave` with `mnt_slave_list` empty. Callers that want
/// PRIVATE/UNBINDABLE then detach `m` from its master. # C: O(slaves + peers)
fn do_make_slave(m: &Arc<Mount>) {
    let pg = m.peer_group.load(Ordering::Acquire);
    let shared_with_peers = Propagation::from_u8(m.propagation.load(Ordering::Acquire)) == Propagation::Shared
        && pg != 0;
    // Choose the master that inherits `m` and its slaves.
    let master: Option<Arc<Mount>> = if shared_with_peers {
        mounts_in_ns(m.ns).into_iter().find(|p| {
            p.mnt_id != m.mnt_id
                && Propagation::from_u8(p.propagation.load(Ordering::Acquire)) == Propagation::Shared
                && p.peer_group.load(Ordering::Acquire) == pg
        })
    } else {
        m.mnt_master.lock().upgrade()
    };
    // Leaving the peer group: drop the shared group id (Linux CLEAR_MNT_SHARED).
    if shared_with_peers { m.peer_group.store(0, Ordering::Release); }
    // Detach `m`'s own slave list once; re-home each entry onto the master.
    let slaves: Vec<Weak<Mount>> = core::mem::take(&mut *m.mnt_slave_list.lock());
    match master {
        Some(master) => {
            for w in slaves.iter() {
                if let Some(s) = w.upgrade() { *s.mnt_master.lock() = Arc::downgrade(&master); }
            }
            {
                let mut ml = master.mnt_slave_list.lock();
                ml.extend(slaves);
                // `m` itself becomes a slave of `master` (exactly once).
                ml.retain(|w| w.upgrade().map(|x| x.mnt_id != m.mnt_id).unwrap_or(true));
                ml.push(Arc::downgrade(m));
            }
            *m.mnt_master.lock() = Arc::downgrade(&master);
        }
        None => {
            // No master to inherit: orphan the slaves (Linux while-loop clears
            // each slave's `mnt_master`).
            for w in slaves.iter() {
                if let Some(s) = w.upgrade() { *s.mnt_master.lock() = Weak::new(); }
            }
            *m.mnt_master.lock() = Weak::new();
        }
    }
    m.propagation.store(Propagation::Slave as u8, Ordering::Release);
}

/// Detach `m` from its master's slave list, then drop the master link.
/// # C: O(master slaves)
fn unlink_from_master(m: &Arc<Mount>) {
    if let Some(master) = m.mnt_master.lock().upgrade() {
        master.mnt_slave_list.lock()
            .retain(|w| w.upgrade().map(|x| x.mnt_id != m.mnt_id).unwrap_or(false));
    }
    *m.mnt_master.lock() = Weak::new();
}

/// Retune the propagation type of the mount at dentry `d` (`docs/16§6`),
/// faithful to Linux `change_mnt_propagation`: MS_SHARED assigns/keeps a peer
/// group; MS_SLAVE/MS_PRIVATE/MS_UNBINDABLE all funnel through [`do_make_slave`]
/// first (re-homing this mount's slaves to its inheriting master), then
/// PRIVATE/UNBINDABLE additionally detach from that master. # C: O(N_mounts)
pub fn set_propagation(d: &Arc<Dentry>, kind: Propagation) -> KResult<()> {
    let m = mount_exact_at(current_ns(), d).ok_or(VfsError::Einval)?;
    match kind {
        Propagation::Shared => {
            if m.peer_group.load(Ordering::Acquire) == 0 {
                m.peer_group.store(super::NEXT_PEER_GROUP.fetch_add(1, Ordering::Relaxed), Ordering::Release);
            }
            m.propagation.store(Propagation::Shared as u8, Ordering::Release);
        }
        Propagation::Slave => {
            do_make_slave(&m);
            // `master:<pg>` mountinfo render reads the MASTER's group id.
            let mpg = m.mnt_master.lock().upgrade()
                .map(|x| x.peer_group.load(Ordering::Acquire)).unwrap_or(0);
            m.peer_group.store(mpg, Ordering::Release);
            m.propagation.store(Propagation::Slave as u8, Ordering::Release);
        }
        Propagation::Private | Propagation::Unbindable => {
            do_make_slave(&m);
            unlink_from_master(&m);
            m.peer_group.store(0, Ordering::Release);
            m.propagation.store(kind as u8, Ordering::Release);
        }
    }
    mntns::bump_gen(m.ns);
    Ok(())
}
