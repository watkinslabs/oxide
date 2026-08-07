// `/proc/<pid>/status` credential copy-out. The task stores internal ids;
// this boundary turns them into the numbers the proc mount's user namespace
// exposes, including the Linux overflow value for an unmapped credential.

use alloc::vec::Vec;

use namespace_identity::NamespaceRef;
use user_namespace::IdMapKind;

/// Namespace-relative uid/gid rows for one proc status view. # C: O(groups)
pub(crate) fn translate(owner: &NamespaceRef, uid: [u32; 4], gid: [u32; 4], groups: &[u32])
    -> ([u32; 4], [u32; 4], Vec<u32>)
{
    let uid = uid.map(|id| out(owner, IdMapKind::Uid, id));
    let gid = gid.map(|id| out(owner, IdMapKind::Gid, id));
    let groups = groups.iter().map(|&id| out(owner, IdMapKind::Gid, id)).collect();
    (uid, gid, groups)
}

fn out(owner: &NamespaceRef, kind: IdMapKind, id: u32) -> u32 {
    user_namespace::resolve_to_ns(owner, kind, id).unwrap_or(kind.overflow().value())
}

#[cfg(test)]
mod tests {
    use namespace_identity::{allocate, initial, NamespaceKind};
    use user_namespace::{IdMapExtent, IdMapKind, write_map};

    use super::*;

    #[test]
    fn proc_status_uses_the_mount_user_namespace_for_every_credential_id() {
        let init = initial(NamespaceKind::User);
        let view = allocate(NamespaceKind::User, init.clone(), Some(init)).unwrap();
        write_map(&view, IdMapKind::Uid, true, 0,
            &[IdMapExtent { ns_id: 7, host_id: 100_000, count: 8 }]).unwrap();
        write_map(&view, IdMapKind::Gid, true, 0,
            &[IdMapExtent { ns_id: 19, host_id: 200_000, count: 4 }]).unwrap();

        let (uid, gid, groups) = translate(&view,
            [100_000, 100_001, 100_007, 42], [200_000, 200_003, 9, 200_001],
            &[200_002, 9]);

        assert_eq!(uid, [7, 8, 14, user_namespace::OVERFLOW_UID]);
        assert_eq!(gid, [19, 22, user_namespace::OVERFLOW_GID, 20]);
        assert_eq!(groups, [21, user_namespace::OVERFLOW_GID]);
    }
}
