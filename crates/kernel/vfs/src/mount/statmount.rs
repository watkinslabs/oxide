// `statmount(2)` / `listmount(2)` fact gathering (`docs/16§6`).
//
// The syscall slots own the ABI (request parsing, the `struct statmount`
// byte layout, the field mask); this module owns the VFS side — which mount a
// request names, whether the caller may see it, and the VALUES of every field
// `statmount` can report. Nothing here formats a user buffer.
//
// [D30] `mnt_id` vs `mnt_id_unique`. Linux carries TWO ids per mount: a small
// recycled `int mnt_id` (mountinfo field 1) and a 64-bit never-recycled
// `mnt_id_unique` starting above [`MNT_UNIQUE_ID_OFFSET`], which is the ONLY id
// `statmount`/`listmount` accept or emit — the offset is load-bearing ABI,
// because a request naming an id at or below it is `EINVAL` and userspace
// probes that. This tree's `Mount::mnt_id` is ALREADY a 64-bit never-recycled
// counter, so it needs no second index and no second allocator: the unique id
// is the pure, bijective function `MNT_UNIQUE_ID_OFFSET + mnt_id`. One id,
// stored once, two ABI presentations — not two sources of truth.

use super::*;

/// Linux `MNT_UNIQUE_ID_OFFSET`: the floor above which every unique mount id
/// lives. A `statmount`/`listmount` request naming an id at or below it is
/// malformed, which is how userspace tells the two id spaces apart. # C: const
pub const MNT_UNIQUE_ID_OFFSET: u64 = 1 << 31;

/// The unique (`statmount`/`listmount`) id of a mount. # C: O(1)
pub fn unique_mnt_id(mnt_id: u64) -> u64 { MNT_UNIQUE_ID_OFFSET + mnt_id }

/// The tree-internal `mnt_id` behind a unique id, or `None` when the value is
/// not a well-formed unique id. # C: O(1)
pub fn mnt_id_from_unique(unique: u64) -> Option<u64> {
    if unique <= MNT_UNIQUE_ID_OFFSET { return None; }
    Some(unique - MNT_UNIQUE_ID_OFFSET)
}

/// Linux `lookup_mnt_in_ns`: the mount named by a UNIQUE id, restricted to
/// namespace `ns`. # C: O(log N)
pub fn mount_by_unique_id_in_ns(unique: u64, ns: u64) -> Option<Arc<Mount>> {
    let m = mount_by_id(mnt_id_from_unique(unique)?)?;
    if m.namespace_id() != ns { return None; }
    Some(m)
}

/// Every mount owned by namespace `ns`, `mnt_id`-ascending — the read side
/// `listmount(2)` and the foreign-namespace root pick walk. # C: O(N_ns)
pub fn mounts_in_ns_snapshot(ns: u64) -> Vec<Arc<Mount>> { mounts_in_ns(ns) }

/// Linux `mnt_to_attr_flags`: the mount's per-mount option bits rendered back
/// into the `MOUNT_ATTR_*` request space `mount_setattr(2)` speaks. The atime
/// policy is a SUB-FIELD with exactly one value, and `MOUNT_ATTR_RELATIME` is
/// its zero, so relatime contributes no bit. # C: O(1)
pub fn mnt_to_attr_flags(m: &Mount) -> u64 {
    let f = m.flags();
    let mut attr = 0u64;
    if f & MNT_RDONLY      != 0 { attr |= MOUNT_ATTR_RDONLY; }
    if f & MNT_NOSUID      != 0 { attr |= MOUNT_ATTR_NOSUID; }
    if f & MNT_NODEV       != 0 { attr |= MOUNT_ATTR_NODEV; }
    if f & MNT_NOEXEC      != 0 { attr |= MOUNT_ATTR_NOEXEC; }
    if f & MNT_NODIRATIME  != 0 { attr |= MOUNT_ATTR_NODIRATIME; }
    if f & MNT_NOSYMFOLLOW != 0 { attr |= MOUNT_ATTR_NOSYMFOLLOW; }
    match m.atime_policy() {
        AtimePolicy::Noatime  => attr |= MOUNT_ATTR_NOATIME,
        AtimePolicy::Relatime => {}
        AtimePolicy::Strict   => attr |= MOUNT_ATTR_STRICTATIME,
    }
    if !m.idmap().is_identity() { attr |= MOUNT_ATTR_IDMAP; }
    attr
}

/// True iff `m` receives propagation from a master (Linux `IS_MNT_SLAVE`) —
/// read from the `mnt_master` LINK, which is the state that actually decides
/// where propagation flows, not from the propagation-type discriminant.
/// # C: O(1)
pub fn is_slave(m: &Mount) -> bool { m.mnt_master.lock().upgrade().is_some() }

/// Linux `mnt_to_propagation_flags`: the `MS_{SHARED,SLAVE,UNBINDABLE}` bits a
/// mount carries, with `MS_PRIVATE` reported when it carries none. Shared and
/// slave are INDEPENDENT in Linux (a slave may also be shared), so both bits
/// can appear together. # C: O(1)
pub fn mnt_to_propagation_flags(m: &Mount) -> u64 {
    let mut p = 0u64;
    match Propagation::from_u8(m.propagation.load(Ordering::Acquire)) {
        Propagation::Shared     => p |= MS_SHARED,
        Propagation::Unbindable => p |= MS_UNBINDABLE,
        Propagation::Slave | Propagation::Private => {}
    }
    if is_slave(m) { p |= MS_SLAVE; }
    if p == 0 { p |= MS_PRIVATE; }
    p
}

/// Linux `mnt_master->mnt_group_id` — the peer group this mount receives
/// propagation FROM, or `0` when it is not a slave. # C: O(1)
pub fn master_group_id(m: &Mount) -> u64 {
    m.mnt_master.lock().upgrade().map(|x| x.peer_group.load(Ordering::Acquire)).unwrap_or(0)
}

/// Linux `get_dominating_id`: walk the master chain and report the peer group
/// of the first master that has a peer REACHABLE from `root` — the group a
/// reader confined to `root` would see the propagation as coming from. `0` when
/// no master is visible there. # C: O(masters × peers × depth)
pub fn dominating_group_id(m: &Mount, root_mnt: u64, root_d: &Arc<Dentry>) -> u64 {
    let ns = m.namespace_id();
    let mut cur = m.mnt_master.lock().upgrade();
    while let Some(master) = cur {
        let pg = master.peer_group.load(Ordering::Acquire);
        if pg != 0 {
            for peer in mounts_in_ns(ns) {
                if peer.peer_group.load(Ordering::Acquire) != pg { continue; }
                if super::reachable::mount_reachable_from(peer.mnt_id, root_mnt, root_d) {
                    return pg;
                }
            }
        }
        cur = master.mnt_master.lock().upgrade();
    }
    0
}

/// Every VFS-owned value `statmount(2)` can report for one mount. Gathered in
/// ONE pass so the reported fields cannot disagree with each other; the syscall
/// slot then emits only the subset the caller's mask requested.
pub struct MountFacts {
    /// `mnt_id` (unique form) and `mnt_parent_id` (unique form).
    pub mnt_id: u64,
    pub mnt_parent_id: u64,
    /// `mnt_id_old` / `mnt_parent_id_old` — the mountinfo field-1 id space.
    pub mnt_id_old: u32,
    pub mnt_parent_id_old: u32,
    pub sb_dev_major: u32,
    pub sb_dev_minor: u32,
    pub sb_magic: u64,
    pub sb_flags: u32,
    pub mnt_attr: u64,
    pub mnt_propagation: u64,
    pub mnt_peer_group: u64,
    pub mnt_master: u64,
    pub propagate_from: u64,
    pub mnt_ns_id: u64,
    pub fs_type: String,
    /// Mount root relative to the filesystem root (mountinfo field 4).
    pub mnt_root: String,
    /// Mount point relative to the CALLER's root, or `None` when the mount is
    /// not under it (Linux `SEQ_SKIP` — the field is then simply absent).
    pub mnt_point: Option<String>,
    /// `show_options` tail WITHOUT its leading comma.
    pub mnt_opts: String,
    pub sb_source: String,
    /// Backend subtype (Linux `sb->s_subtype`); empty when the filesystem has
    /// none, in which case the field is absent rather than empty.
    pub fs_subtype: String,
    /// `true` once the mount carries a non-identity idmap; the uid/gid map
    /// fields are reported (possibly as zero mappings) only then.
    pub idmapped: bool,
    pub uid_extents: Vec<crate::idmap::IdExtent>,
    pub gid_extents: Vec<crate::idmap::IdExtent>,
}

/// Superblock flags `statmount` reports (Linux masks `sb->s_flags` down to
/// exactly these four). # C: const
const SB_REPORTED_MASK: u64 = crate::superblock::SB_RDONLY | crate::superblock::SB_SYNCHRONOUS
    | crate::superblock::SB_DIRSYNC | crate::superblock::SB_LAZYTIME;

/// Gather every reportable fact for mount `mnt_id`, with paths rendered
/// relative to the `(root_mnt, root_d)` the caller resolves from. # C: O(depth + N_ns)
pub fn statmount_facts(mnt_id: u64, root_mnt: u64, root_d: &Arc<Dentry>) -> Option<MountFacts> {
    let m = mount_by_id(mnt_id)?;
    let sb = m.sb();
    let dev = sb.s_dev;
    let parent = m.parent_id.load(Ordering::Acquire);
    let idmap = m.idmap();
    let root_str = render_path_for_mount(root_mnt, root_d);
    let point = if super::reachable::mount_reachable_from(mnt_id, root_mnt, root_d) {
        project_path_under_root(&m.mount_point_str(),
            if root_str == "/" { None } else { Some(root_str.as_str()) })
    } else { None };
    // `show_options` emits each option self-comma-prefixed (the seq_file
    // convention every backend follows); statmount reports the tail without
    // that leading separator.
    let raw_opts = sb.show_options();
    let opts = raw_opts.strip_prefix(',').unwrap_or(&raw_opts);
    Some(MountFacts {
        mnt_id: unique_mnt_id(mnt_id),
        mnt_parent_id: unique_mnt_id(parent),
        mnt_id_old: mnt_id as u32,
        mnt_parent_id_old: parent as u32,
        sb_dev_major: (dev >> crate::devnode::MINORBITS) as u32,
        sb_dev_minor: (dev & crate::devnode::MINORMASK as u64) as u32,
        sb_magic: sb.s_magic,
        sb_flags: (sb.s_flags() & SB_REPORTED_MASK) as u32,
        mnt_attr: mnt_to_attr_flags(&m),
        mnt_propagation: mnt_to_propagation_flags(&m),
        mnt_peer_group: m.peer_group.load(Ordering::Acquire),
        mnt_master: master_group_id(&m),
        propagate_from: dominating_group_id(&m, root_mnt, root_d),
        mnt_ns_id: m.namespace_id(),
        fs_type: String::from(sb.s_type.name()),
        mnt_root: mountinfo_root_field(&m),
        mnt_point: point,
        mnt_opts: String::from(opts),
        sb_source: mountinfo_source_field(&m),
        // No backend in this tree publishes a subtype, so the field is always
        // absent — exactly what Linux emits for `sb->s_subtype == NULL`.
        fs_subtype: String::new(),
        idmapped: !idmap.is_identity(),
        uid_extents: idmap.uid_extents().to_vec(),
        gid_extents: idmap.gid_extents().to_vec(),
    })
}

/// Linux `do_listmount`'s selection: every mount of `ns` that lies at or below
/// the subtree rooted at `orig_mnt`, in `mnt_id` order, excluding `orig_mnt`
/// itself when the caller named it explicitly. Returns UNIQUE ids.
///
/// `after` is the cursor (`mnt_id_req.param`, a unique id): forward listing
/// resumes strictly after it, reverse listing strictly before it. `0` starts at
/// the corresponding end. # C: O(N_ns × depth)
pub fn listmount_ids(ns: u64, orig_mnt: u64, skip_orig: bool, after: u64, reverse: bool,
                     limit: usize) -> Vec<u64> {
    let Some(orig_root) = mount_by_id(orig_mnt).and_then(|m| m.mnt_root()) else { return Vec::new(); };
    let mut all = mounts_in_ns(ns);
    if reverse { all.reverse(); }
    let mut out = Vec::new();
    for m in all {
        if out.len() >= limit { break; }
        let uid = unique_mnt_id(m.mnt_id);
        if after != 0 {
            if reverse { if uid >= after { continue; } } else if uid <= after { continue; }
        }
        if skip_orig && m.mnt_id == orig_mnt { continue; }
        if !super::reachable::mount_reachable_from(m.mnt_id, orig_mnt, &orig_root) { continue; }
        out.push(uid);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unique_id_is_above_the_offset_and_round_trips() {
        assert_eq!(unique_mnt_id(1), MNT_UNIQUE_ID_OFFSET + 1);
        assert_eq!(mnt_id_from_unique(MNT_UNIQUE_ID_OFFSET + 1), Some(1));
    }

    #[test]
    fn an_id_at_or_below_the_offset_is_not_a_unique_id() {
        // The rung `statmount`/`listmount` expose as EINVAL: userspace probes
        // it to tell the two mount-id spaces apart.
        assert_eq!(mnt_id_from_unique(0), None);
        assert_eq!(mnt_id_from_unique(1), None);
        assert_eq!(mnt_id_from_unique(MNT_UNIQUE_ID_OFFSET), None);
        assert!(mnt_id_from_unique(MNT_UNIQUE_ID_OFFSET + 1).is_some());
    }
}
