/// `mntget` (Linux `mntget`): pin a long-lived external reference on `m`. # C: O(1)
pub fn mntget(m: &Arc<Mount>) {
    m.mnt_count.fetch_add(1, Ordering::AcqRel);
    m.mnt_internal_flags.fetch_and(!MNT_EXPIRE_MARK, Ordering::AcqRel);
}

/// `mntput` (Linux `mntput_no_expire`): drop a long-lived mount reference.
/// # C: O(1) (O(tree) on last)
pub fn mntput(m: &Arc<Mount>) {
    let prev = m.mnt_count.fetch_sub(1, Ordering::AcqRel);
    hal::kassert!(prev > 0, "mntput: mnt_count underflow below zero");
    if prev == 1 && m.detached.load(Ordering::Acquire) {
        put_super_if_last(&m.sb);
    }
}

/// Unlink `id` from its parent's intrusive child list. # C: O(siblings)
fn unlink_from_parent(m: &Arc<Mount>) {
    if let Some(p) = m.mnt_parent.lock().upgrade() {
        p.mnt_mounts.lock().retain(|c| c.mnt_id != m.mnt_id);
    }
}

/// Copy-on-unshare / `copy_mnt_ns` (`docs/16§6`). # C: O(N_mounts × depth)
pub fn copy_mnt_ns(from_ns: u64, to_ns: u64) {
    let _ = copy_mnt_ns_map(from_ns, to_ns);
}

/// As [`copy_mnt_ns`], returning the old→new mount id mapping so live
/// `struct path` references can be translated into the copied tree.
/// # C: O(N_mounts × depth)
pub fn copy_mnt_ns_map(from_ns: u64, to_ns: u64) -> Vec<(u64, u64)> {
    let src = mounts_in_ns(from_ns);
    let from_root = root_mount_id(from_ns);
    mntns::ns_get_or_create(to_ns);
    let mut map = Vec::new();
    let _w = MOUNT_WRITE.lock();
    for m in src.iter() {
        let prop = Propagation::from_u8(m.propagation.load(Ordering::Acquire));
        let clone = match prop {
            Propagation::Shared => {
                let c = clone_mnt(m, CloneType::Slave, 0, m, to_ns);
                c.peer_group.store(m.peer_group.load(Ordering::Acquire), Ordering::Release);
                c
            }
            _ => clone_mnt(m, CloneType::Private, 0, m, to_ns),
        };
        *clone.mountpoint.lock() = m.mountpoint();
        map.push((m.mnt_id, clone.mnt_id));
        // Linux copies `mnt_ns->root`; do not infer root from parent fields.
        if Some(m.mnt_id) == from_root { mntns::ns_set_root(to_ns, clone.mnt_id); }
        MOUNTS.lock().insert(clone.mnt_id, clone);
    }
    mntns::commit_mounts(to_ns, src.len() as u64);
    rebuild_ns_index(to_ns);
    mntns::bump_gen(to_ns);
    map
}

/// Back-compat alias for the unshare(CLONE_NEWNS) call site. # C: O(N×depth)
pub fn snapshot_ns(from_ns: u64, to_ns: u64) { copy_mnt_ns(from_ns, to_ns); }

/// Snapshot alias that exposes the old→new mount id map. # C: O(N×depth)
pub fn snapshot_ns_map(from_ns: u64, to_ns: u64) -> Vec<(u64, u64)> {
    copy_mnt_ns_map(from_ns, to_ns)
}

/// Reap every mount belonging to `ns` (Linux `free_mnt_ns`). # C: O(N_ns_mounts)
pub(crate) fn reap_ns(ns: u64) {
    let mounts = mounts_in_ns(ns);
    for m in mounts.iter() {
        if let Some(o) = m.mnt_mp.lock().take() { put_mountpoint(&o); }
        m.mnt_mounts.lock().clear();
        MOUNTS.lock().remove(&m.mnt_id);
        put_super_if_last(&m.sb);
    }
    mntns::dec_mounts(ns, mounts.len() as u64);
    hash_drop_ids(&mounts.iter().map(|m| m.mnt_id).collect::<Vec<_>>());
    mntns::bump_gen(ns);
}
