// Linux `make_kuid`/`make_kgid` and `from_kuid_munged`/`from_kgid_munged`
// bound to a NAMESPACE rather than a bare extent slice (`translate.rs` owns
// the arithmetic; this file owns "which map").
//
// Direction names the ABI edge, not the map orientation:
//   * `to_host` — a uid/gid ARGUMENT arriving from userspace becomes the
//     internal id every subsystem compares against (`make_k*id`). Unmapped
//     is `None`, Linux's `INVALID_UID`, which is an error at every call site
//     that is not a `-1` sentinel.
//   * `to_ns` — an internal id leaving the kernel becomes the number this
//     namespace's userspace can name (`from_k*id_munged`). Unmapped munges
//     to the overflow id, never fails.

use namespace_identity::Namespace;

use crate::engine::{with_map, IdMapKind, UserNsError};
use crate::uapi::INVALID_ID;
use crate::translate;

/// Linux `make_kuid(ns, id)` / `make_kgid(ns, id)`. `None` is `INVALID_UID`:
/// either the id has no extent covering it, or it is the `(uid_t)-1`
/// sentinel, which Linux's maps can never cover because the identity extent
/// of the initial namespace stops one short of it. # C: O(extents)
pub fn to_host<H: core::ops::Deref<Target = Namespace>>(owner: &H, kind: IdMapKind, ns_id: u32)
    -> Result<Option<u32>, UserNsError>
{
    if ns_id == INVALID_ID { return Ok(None); }
    with_map(owner, kind, |map| translate::to_host_checked(map, ns_id))
}

/// Linux `from_kuid_munged(ns, kuid)` / `from_kgid_munged(ns, kgid)`.
/// # C: O(extents)
pub fn to_ns<H: core::ops::Deref<Target = Namespace>>(owner: &H, kind: IdMapKind, host_id: u32)
    -> Result<u32, UserNsError>
{
    with_map(owner, kind, |map| translate::to_ns(map, host_id, kind.overflow()))
}

/// Linux `from_kuid(ns, kuid) != (uid_t)-1`: is this internal id nameable
/// inside the namespace at all? Distinct from [`to_ns`], which cannot tell
/// an unmapped id from one genuinely mapped to the overflow id.
/// # C: O(extents)
pub fn is_mapped<H: core::ops::Deref<Target = Namespace>>(owner: &H, kind: IdMapKind, host_id: u32)
    -> Result<bool, UserNsError>
{
    with_map(owner, kind, |map| translate::has_mapping(map, host_id))
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use namespace_identity::{allocate, initial, NamespaceKind};

    use super::*;
    use crate::extent::IdMapExtent;
    use crate::engine::write_map;
    use crate::uapi::{OVERFLOW_GID, OVERFLOW_UID};

    fn child() -> namespace_identity::NamespaceRef {
        let init = initial(NamespaceKind::User);
        allocate(NamespaceKind::User, init.clone(), Some(init)).unwrap()
    }

    #[test]
    fn initial_namespace_is_the_identity_map_in_both_directions() {
        let init = initial(NamespaceKind::User);
        for id in [0u32, 1, 1000, 65534, u32::MAX - 1] {
            assert_eq!(to_host(&init, IdMapKind::Uid, id), Ok(Some(id)));
            assert_eq!(to_ns(&init, IdMapKind::Uid, id), Ok(id));
            assert_eq!(is_mapped(&init, IdMapKind::Gid, id), Ok(true));
        }
    }

    #[test]
    fn the_minus_one_sentinel_never_maps_even_in_the_initial_namespace() {
        let init = initial(NamespaceKind::User);
        assert_eq!(to_host(&init, IdMapKind::Uid, INVALID_ID), Ok(None));
        assert_eq!(to_host(&init, IdMapKind::Gid, INVALID_ID), Ok(None));
        // The initial identity extent deliberately stops one id short, so the
        // sentinel is unmapped in the OUT direction too.
        assert_eq!(is_mapped(&init, IdMapKind::Uid, INVALID_ID), Ok(false));
    }

    #[test]
    fn an_unwritten_child_map_maps_nothing_in_and_overflows_everything_out() {
        let ns = child();
        assert_eq!(to_host(&ns, IdMapKind::Uid, 0), Ok(None));
        assert_eq!(to_ns(&ns, IdMapKind::Uid, 0), Ok(OVERFLOW_UID));
        assert_eq!(to_ns(&ns, IdMapKind::Gid, 0), Ok(OVERFLOW_GID));
        assert_eq!(is_mapped(&ns, IdMapKind::Uid, 0), Ok(false));
    }

    #[test]
    fn a_written_child_map_round_trips_its_own_range_only() {
        let ns = child();
        write_map(&ns, IdMapKind::Uid, true, 0,
            &[IdMapExtent { ns_id: 0, host_id: 100_000, count: 65_536 }]).unwrap();
        assert_eq!(to_host(&ns, IdMapKind::Uid, 0), Ok(Some(100_000)));
        assert_eq!(to_host(&ns, IdMapKind::Uid, 65_535), Ok(Some(165_535)));
        assert_eq!(to_host(&ns, IdMapKind::Uid, 65_536), Ok(None));
        assert_eq!(to_ns(&ns, IdMapKind::Uid, 100_000), Ok(0));
        assert_eq!(to_ns(&ns, IdMapKind::Uid, 99_999), Ok(OVERFLOW_UID));
        // The gid map is independent and still unwritten.
        assert_eq!(to_host(&ns, IdMapKind::Gid, 0), Ok(None));
    }

    #[test]
    fn a_non_user_namespace_has_no_id_map() {
        let uts = allocate(NamespaceKind::Uts, initial(NamespaceKind::User), None).unwrap();
        assert_eq!(to_host(&uts, IdMapKind::Uid, 0), Err(UserNsError::WrongKind));
        assert_eq!(to_ns(&uts, IdMapKind::Uid, 0), Err(UserNsError::WrongKind));
    }

    #[test]
    fn with_map_sees_every_extent_of_a_multi_extent_write() {
        let ns = child();
        let extents = vec![
            IdMapExtent { ns_id: 0, host_id: 1000, count: 1 },
            IdMapExtent { ns_id: 1, host_id: 200_000, count: 10 },
        ];
        write_map(&ns, IdMapKind::Gid, true, 0, &extents).unwrap();
        assert_eq!(to_host(&ns, IdMapKind::Gid, 0), Ok(Some(1000)));
        assert_eq!(to_host(&ns, IdMapKind::Gid, 10), Ok(Some(200_009)));
        assert_eq!(to_host(&ns, IdMapKind::Gid, 11), Ok(None));
    }
}
