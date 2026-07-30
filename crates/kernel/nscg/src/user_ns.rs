use alloc::vec::Vec;

use namespace_identity::NamespaceRef;
use vfs::idmap::{IdExtent, Idmap};

pub use user_namespace::*;

/// Snapshot one user namespace's canonical uid/gid maps into the immutable
/// per-mount form Linux builds in `alloc_mnt_idmap()`. The user-namespace map
/// is `<namespace id, host/kernel id, count>`; a mount idmap translates an
/// inode's host/kernel owner to the namespace-visible id, hence
/// `fs_lo = host_id` and `vfs_lo = ns_id`.
///
/// An unset uid or gid map is `EINVAL` in Linux's `copy_mnt_idmap`, represented
/// here by the existing `EmptyExtents` error. The initial namespace policy
/// (`EPERM`) belongs to the syscall admission ladder; this function only
/// performs the single canonical representation conversion.
/// # C: O(uid extents + gid extents)
pub fn mount_idmap(owner: &NamespaceRef) -> Result<Idmap, UserNsError> {
    fn convert(extents: Vec<IdMapExtent>) -> Result<Vec<IdExtent>, UserNsError> {
        if extents.is_empty() { return Err(UserNsError::EmptyExtents); }
        Ok(extents.into_iter().map(|e| IdExtent {
            fs_lo: e.host_id,
            vfs_lo: e.ns_id,
            count: e.count,
        }).collect())
    }

    let uid = convert(snapshot_map(owner, IdMapKind::Uid)?)?;
    let gid = convert(snapshot_map(owner, IdMapKind::Gid)?)?;
    Ok(Idmap::new(uid, gid))
}

#[cfg(test)]
mod tests {
    use namespace_identity::{allocate, initial, NamespaceKind};

    use super::*;

    #[test]
    fn mount_map_uses_host_to_namespace_orientation() {
        let init = initial(NamespaceKind::User);
        let owner = allocate(NamespaceKind::User, init.clone(), Some(init)).unwrap();
        let uid = [IdMapExtent { ns_id: 0, host_id: 100_000, count: 100 }];
        let gid = [IdMapExtent { ns_id: 7, host_id: 200_000, count: 10 }];
        write_map(&owner, IdMapKind::Uid, true, 0, &uid).unwrap();
        write_map(&owner, IdMapKind::Gid, true, 0, &gid).unwrap();

        let map = mount_idmap(&owner).unwrap();
        assert_eq!(map.map_out_uid(100_000), 0);
        assert_eq!(map.map_in_uid(99), 100_099);
        assert_eq!(map.map_out_gid(200_000), 7);
        assert_eq!(map.map_in_gid(16), 200_009);
    }

    #[test]
    fn mount_map_requires_both_written_maps() {
        let init = initial(NamespaceKind::User);
        let owner = allocate(NamespaceKind::User, init.clone(), Some(init)).unwrap();
        write_map(&owner, IdMapKind::Uid, true, 0,
            &[IdMapExtent { ns_id: 0, host_id: 1000, count: 1 }]).unwrap();
        assert_eq!(mount_idmap(&owner).err(), Some(UserNsError::EmptyExtents));
    }
}
