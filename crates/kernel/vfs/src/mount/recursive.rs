/// Graft a mount and propagate it as one mount-engine operation. # C: O(N × depth)
pub fn attach_recursive_mnt(mp: Option<Arc<Dentry>>, fs: Arc<dyn FileSystem>,
                            root: Option<InodeRef>) -> KResult<usize> {
    let at = mp.clone();
    let ty = crate::fs::get_fs_type(fs.name()).ok_or(VfsError::Enodev)?;
    match root {
        Some(r) => register_bind_typed(ty, mp, fs, r)?,
        None => register_typed(ty, mp, fs)?,
    }
    Ok(match at { Some(d) => propagation::propagate_mount(&d), None => 0 })
}

fn subtree_ids(_ns: u64, top: u64) -> Vec<u64> {
    let mut ids = alloc::vec![top];
    let mut frontier: Vec<Arc<Mount>> = mount_by_id(top).into_iter().collect();
    while let Some(m) = frontier.pop() {
        for c in m.mnt_mounts.lock().iter() {
            if !ids.contains(&c.mnt_id) { ids.push(c.mnt_id); frontier.push(c.clone()); }
        }
    }
    ids
}

fn is_shared(m: &Mount) -> bool {
    Propagation::from_u8(m.propagation.load(Ordering::Acquire)) == Propagation::Shared
}

fn is_unbindable(m: &Mount) -> bool {
    Propagation::from_u8(m.propagation.load(Ordering::Acquire)) == Propagation::Unbindable
}

fn tree_contains_unbindable(ns: u64, top: u64) -> bool {
    subtree_ids(ns, top).iter()
        .any(|id| mount_by_id(*id).map(|m| is_unbindable(&m)).unwrap_or(false))
}
