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

/// Convert through the task owner, or the canonical initial TIME owner after task teardown.
/// # C: O(log N)
pub fn absolute_to_host_or_initial(owner: Option<&NamespaceRef>, clock: TimeNsClock, user_ns: u64)
    -> Result<u64, TimeNsError>
{
    match owner {
        Some(owner) => absolute_to_host(owner, clock, user_ns),
        None => absolute_to_host(&namespace_identity::initial(NamespaceKind::Time), clock, user_ns),
    }
}

#[cfg(test)]
pub(crate) fn contains(id: NamespaceId) -> bool { TIME.lock().contains_key(&id) }
