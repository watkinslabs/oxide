// Time namespace offsets keyed by canonical namespace identity.

use alloc::collections::BTreeMap;

use namespace_identity::{NamespaceId, NamespaceKind, NamespaceRef};

pub const NSEC_PER_SEC: i64 = 1_000_000_000;
pub const KTIME_SEC_MAX: i64 = i64::MAX / NSEC_PER_SEC;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TimeOffset {
    pub seconds: i64,
    pub nanoseconds: i32,
}

impl TimeOffset {
    pub const ZERO: Self = Self { seconds: 0, nanoseconds: 0 };

    /// Construct one normalized signed offset. # C: O(1)
    pub fn new(seconds: i64, nanoseconds: i32) -> Result<Self, TimeNsError> {
        let offset = Self { seconds, nanoseconds };
        validate_normalized(offset)?;
        Ok(offset)
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TimeNsOffsets {
    pub monotonic: TimeOffset,
    pub boottime: TimeOffset,
}

impl TimeNsOffsets {
    pub const ZERO: Self = Self { monotonic: TimeOffset::ZERO, boottime: TimeOffset::ZERO };
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TimeNsState {
    pub offsets: TimeNsOffsets,
    pub frozen: bool,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TimeNsClock { Monotonic, Boottime }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TimeNsUpdate {
    pub clock: TimeNsClock,
    pub offset: TimeOffset,
    pub host_ns: u64,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TimeNsError {
    WrongKind, InitialClone, StateExists, StateMissing,
    InvalidOffset, InvalidClockTime, OffsetOutOfRange, Frozen,
}

static TIME: sync::Spinlock<BTreeMap<NamespaceId, TimeNsState>, sync::TaskList> =
    sync::Spinlock::new(BTreeMap::new());

fn owner_id(owner: &NamespaceRef) -> Result<NamespaceId, TimeNsError> {
    if owner.kind() != NamespaceKind::Time { return Err(TimeNsError::WrongKind); }
    Ok(owner.id())
}

fn remove(kind: NamespaceKind, id: NamespaceId) {
    if kind == NamespaceKind::Time { TIME.lock().remove(&id); }
}

fn validate_normalized(value: TimeOffset) -> Result<(), TimeNsError> {
    if value.nanoseconds < 0 || i64::from(value.nanoseconds) >= NSEC_PER_SEC {
        return Err(TimeNsError::InvalidOffset);
    }
    Ok(())
}

fn validate_clock_time(value: TimeOffset) -> Result<(), TimeNsError> {
    if value.nanoseconds < 0 || i64::from(value.nanoseconds) >= NSEC_PER_SEC
        || value.seconds < 0 || value.seconds > KTIME_SEC_MAX / 2
    {
        return Err(TimeNsError::InvalidClockTime);
    }
    Ok(())
}

fn validate_update(update: TimeNsUpdate) -> Result<(), TimeNsError> {
    validate_normalized(update.offset)?;
    if update.offset.seconds > KTIME_SEC_MAX || update.offset.seconds < -KTIME_SEC_MAX {
        return Err(TimeNsError::OffsetOutOfRange);
    }
    let host_seconds = update.host_ns / NSEC_PER_SEC as u64;
    if host_seconds > i64::MAX as u64 { return Err(TimeNsError::InvalidClockTime); }
    let base = TimeOffset {
        seconds: host_seconds as i64,
        nanoseconds: (update.host_ns % NSEC_PER_SEC as u64) as i32,
    };
    validate_clock_time(base)?;
    let mut seconds = i128::from(base.seconds) + i128::from(update.offset.seconds);
    let nanoseconds = i64::from(base.nanoseconds) + i64::from(update.offset.nanoseconds);
    if nanoseconds >= NSEC_PER_SEC { seconds += 1; }
    if seconds < 0 || seconds > i128::from(KTIME_SEC_MAX / 2) {
        return Err(TimeNsError::OffsetOutOfRange);
    }
    Ok(())
}

fn offset_ns(offset: TimeOffset) -> i128 {
    i128::from(offset.seconds) * i128::from(NSEC_PER_SEC) + i128::from(offset.nanoseconds)
}

/// Initialize an unfrozen clone from one exact old time owner. # C: O(log N)
pub fn clone_from(owner: &NamespaceRef, old: &NamespaceRef) -> Result<(), TimeNsError> {
    let id = owner_id(owner)?;
    let old_id = owner_id(old)?;
    if owner.is_initial() { return Err(TimeNsError::InitialClone); }
    let mut states = TIME.lock();
    if states.contains_key(&id) { return Err(TimeNsError::StateExists); }
    let offsets = if old.is_initial() { TimeNsOffsets::ZERO }
        else { states.get(&old_id).ok_or(TimeNsError::StateMissing)?.offsets };
    states.insert(id, TimeNsState { offsets, frozen: false });
    drop(states);
    owner.register_finalizer(remove);
    Ok(())
}

/// Snapshot offsets and frozen state for one exact time owner. # C: O(log N)
pub fn snapshot(owner: &NamespaceRef) -> Result<TimeNsState, TimeNsError> {
    let id = owner_id(owner)?;
    if owner.is_initial() {
        return Ok(TimeNsState { offsets: TimeNsOffsets::ZERO, frozen: true });
    }
    TIME.lock().get(&id).copied().ok_or(TimeNsError::StateMissing)
}

/// Atomically apply validated offset updates to one unfrozen owner. # C: O(N_updates + log N)
pub fn set_offsets(owner: &NamespaceRef, updates: &[TimeNsUpdate]) -> Result<(), TimeNsError> {
    let id = owner_id(owner)?;
    for update in updates { validate_update(*update)?; }
    if owner.is_initial() { return Err(TimeNsError::Frozen); }

    let mut states = TIME.lock();
    let state = states.get_mut(&id).ok_or(TimeNsError::StateMissing)?;
    if state.frozen { return Err(TimeNsError::Frozen); }
    let mut offsets = state.offsets;
    for update in updates {
        match update.clock {
            TimeNsClock::Monotonic => offsets.monotonic = update.offset,
            TimeNsClock::Boottime => offsets.boottime = update.offset,
        }
    }
    state.offsets = offsets;
    Ok(())
}

/// Irreversibly freeze offsets when a task enters this time owner. # C: O(log N)
pub fn freeze(owner: &NamespaceRef) -> Result<(), TimeNsError> {
    let id = owner_id(owner)?;
    if owner.is_initial() { return Ok(()); }
    let mut states = TIME.lock();
    let state = states.get_mut(&id).ok_or(TimeNsError::StateMissing)?;
    state.frozen = true;
    Ok(())
}

/// Add this owner's signed display offset to a host clock value. # C: O(log N)
pub fn apply_display_offset(owner: &NamespaceRef, clock: TimeNsClock, host_ns: u64)
    -> Result<u64, TimeNsError>
{
    let offsets = snapshot(owner)?.offsets;
    let offset = match clock {
        TimeNsClock::Monotonic => offsets.monotonic,
        TimeNsClock::Boottime => offsets.boottime,
    };
    let value = i128::from(host_ns) + offset_ns(offset);
    Ok(value.clamp(0, i128::from(u64::MAX)) as u64)
}

/// Convert an absolute namespaced clock value to a host deadline. # C: O(log N)
pub fn absolute_to_host(owner: &NamespaceRef, clock: TimeNsClock, user_ns: u64)
    -> Result<u64, TimeNsError>
{
    let offsets = snapshot(owner)?.offsets;
    let offset = match clock {
        TimeNsClock::Monotonic => offsets.monotonic,
        TimeNsClock::Boottime => offsets.boottime,
    };
    let value = i128::from(user_ns) - offset_ns(offset);
    Ok(value.clamp(0, i128::from(i64::MAX)) as u64)
}

#[cfg(test)]
pub(crate) fn contains(id: NamespaceId) -> bool { TIME.lock().contains_key(&id) }

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(set_offsets(&owner, &updates),
            Err(TimeNsError::InvalidOffset));
        assert_eq!(snapshot(&owner).unwrap(), before);
        freeze(&owner).unwrap();
        assert_eq!(set_offsets(&owner, &updates),
            Err(TimeNsError::InvalidOffset));
    }

    #[test]
    fn host_plus_offset_range_is_validated() {
        let owner = owner();
        clone_from(&owner, &namespace_identity::initial(NamespaceKind::Time)).unwrap();
        let negative = [TimeNsUpdate { clock: TimeNsClock::Monotonic,
            offset: TimeOffset::new(-11, 0).unwrap(), host_ns: 10_000_000_000 }];
        assert_eq!(set_offsets(&owner, &negative),
            Err(TimeNsError::OffsetOutOfRange));
        let high = [TimeNsUpdate { clock: TimeNsClock::Boottime,
            offset: TimeOffset::new(KTIME_SEC_MAX, 0).unwrap(), host_ns: 10_000_000_000 }];
        assert_eq!(set_offsets(&owner, &high),
            Err(TimeNsError::OffsetOutOfRange));
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
    fn final_owner_drop_removes_exact_state() {
        let owner = owner();
        let id = owner.id();
        clone_from(&owner, &namespace_identity::initial(NamespaceKind::Time)).unwrap();
        assert!(contains(id));
        drop(owner);
        assert!(!contains(id));
    }
}
