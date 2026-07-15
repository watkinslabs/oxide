use namespace_identity::{NamespaceKind, NamespaceRef};

use crate::{absolute_to_host, absolute_to_host_or_initial, apply_display_offset, clone_from,
    freeze, set_offsets, snapshot, TimeNsClock, TimeNsError, TimeNsOffsets, TimeNsState,
    TimeNsUpdate, TimeOffset, KTIME_SEC_MAX};

fn owner() -> NamespaceRef {
    namespace_identity::allocate(NamespaceKind::Time,
        namespace_identity::initial(NamespaceKind::User), None).unwrap()
}

#[test]
fn initial_owner_is_zero_and_frozen() {
    let initial = namespace_identity::initial(NamespaceKind::Time);
    assert_eq!(snapshot(&initial).unwrap(), TimeNsState {
        offsets: TimeNsOffsets::ZERO, frozen: true,
    });
    assert_eq!(set_offsets(&initial, &[]), Err(TimeNsError::Frozen));
    freeze(&initial).unwrap();
}

#[test]
fn clone_inherits_both_offsets_but_not_frozen_state() {
    let old = owner();
    let clone = owner();
    clone_from(&old, &namespace_identity::initial(NamespaceKind::Time)).unwrap();
    set_offsets(&old, &[
        TimeNsUpdate { clock: TimeNsClock::Monotonic,
            offset: TimeOffset::new(-2, 500_000_000).unwrap(), host_ns: 10_000_000_000 },
        TimeNsUpdate { clock: TimeNsClock::Boottime,
            offset: TimeOffset::new(3, 250_000_000).unwrap(), host_ns: 10_000_000_000 },
    ]).unwrap();
    freeze(&old).unwrap();
    clone_from(&clone, &old).unwrap();
    assert_eq!(snapshot(&clone).unwrap(), TimeNsState {
        offsets: snapshot(&old).unwrap().offsets, frozen: false,
    });
}

#[test]
fn invalid_batch_does_not_partially_update_and_validation_precedes_freeze() {
    let owner = owner();
    clone_from(&owner, &namespace_identity::initial(NamespaceKind::Time)).unwrap();
    let before = snapshot(&owner).unwrap();
    let updates = [
        TimeNsUpdate { clock: TimeNsClock::Monotonic,
            offset: TimeOffset::new(1, 0).unwrap(), host_ns: 10_000_000_000 },
        TimeNsUpdate { clock: TimeNsClock::Boottime,
            offset: TimeOffset { seconds: 0, nanoseconds: 1_000_000_000 },
            host_ns: 10_000_000_000 },
    ];
    assert_eq!(set_offsets(&owner, &updates), Err(TimeNsError::InvalidOffset));
    assert_eq!(snapshot(&owner).unwrap(), before);
    freeze(&owner).unwrap();
    assert_eq!(set_offsets(&owner, &updates), Err(TimeNsError::InvalidOffset));
}

#[test]
fn host_plus_offset_range_is_validated() {
    let owner = owner();
    clone_from(&owner, &namespace_identity::initial(NamespaceKind::Time)).unwrap();
    let negative = [TimeNsUpdate { clock: TimeNsClock::Monotonic,
        offset: TimeOffset::new(-11, 0).unwrap(), host_ns: 10_000_000_000 }];
    assert_eq!(set_offsets(&owner, &negative), Err(TimeNsError::OffsetOutOfRange));
    let high = [TimeNsUpdate { clock: TimeNsClock::Boottime,
        offset: TimeOffset::new(KTIME_SEC_MAX, 0).unwrap(), host_ns: 10_000_000_000 }];
    assert_eq!(set_offsets(&owner, &high), Err(TimeNsError::OffsetOutOfRange));
}

#[test]
fn entry_freezes_exact_owner_only() {
    let first = owner();
    let second = owner();
    let initial = namespace_identity::initial(NamespaceKind::Time);
    clone_from(&first, &initial).unwrap();
    clone_from(&second, &initial).unwrap();
    freeze(&first).unwrap();
    assert!(snapshot(&first).unwrap().frozen);
    assert!(!snapshot(&second).unwrap().frozen);
    set_offsets(&second, &[TimeNsUpdate { clock: TimeNsClock::Monotonic,
        offset: TimeOffset::new(1, 0).unwrap(), host_ns: 10_000_000_000 }]).unwrap();
}

#[test]
fn signed_display_and_absolute_conversions_saturate() {
    let owner = owner();
    clone_from(&owner, &namespace_identity::initial(NamespaceKind::Time)).unwrap();
    set_offsets(&owner, &[
        TimeNsUpdate { clock: TimeNsClock::Monotonic,
            offset: TimeOffset::new(-2, 500_000_000).unwrap(), host_ns: 10_000_000_000 },
        TimeNsUpdate { clock: TimeNsClock::Boottime,
            offset: TimeOffset::new(3, 0).unwrap(), host_ns: 10_000_000_000 },
    ]).unwrap();
    assert_eq!(apply_display_offset(&owner, TimeNsClock::Monotonic, 4_000_000_000),
        Ok(2_500_000_000));
    assert_eq!(apply_display_offset(&owner, TimeNsClock::Monotonic, 1_000_000_000), Ok(0));
    assert_eq!(absolute_to_host(&owner, TimeNsClock::Boottime, 2_000_000_000), Ok(0));
    assert_eq!(absolute_to_host(&owner, TimeNsClock::Monotonic, 2_500_000_000),
        Ok(4_000_000_000));
}

#[test]
fn missing_task_owner_uses_initial_time_namespace() {
    assert_eq!(absolute_to_host_or_initial(None, TimeNsClock::Monotonic, 7_000_000_000),
        Ok(7_000_000_000));
    assert_eq!(absolute_to_host_or_initial(None, TimeNsClock::Boottime, 9_000_000_000),
        Ok(9_000_000_000));
}

#[test]
fn final_owner_drop_removes_exact_state() {
    let owner = owner();
    let id = owner.id();
    clone_from(&owner, &namespace_identity::initial(NamespaceKind::Time)).unwrap();
    assert!(crate::state::contains(id));
    drop(owner);
    assert!(!crate::state::contains(id));
}
