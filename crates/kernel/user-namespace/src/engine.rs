// USER namespace uid_map/gid_map/setgroups state keyed by canonical
// namespace identity (`docs/26§2` invariant 6, `docs/26§3.6`). One canonical
// copy per exact `User` namespace owner — consumers (procfs, credential
// translation) read/write through this engine, never a parallel copy.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use namespace_identity::{Namespace, NamespaceId, NamespaceKind, NamespaceRef};

use crate::extent::{validate_extents, ExtentError, IdMapExtent};
use crate::translate::OverflowId;
use crate::uapi::{INITIAL_COUNT, INITIAL_HOST_ID, INITIAL_NS_ID};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum IdMapKind { Uid, Gid }

impl IdMapKind {
    /// Overflow id this map kind translates an unmapped id to. # C: O(1)
    pub const fn overflow(self) -> OverflowId {
        match self { Self::Uid => OverflowId::Uid, Self::Gid => OverflowId::Gid }
    }
}

/// Linux `/proc/<pid>/setgroups` value (`kernel/user_namespace.c`
/// `proc_setgroups_write`). Default `Allow`; `Deny` is a one-way door once
/// `gid_map` is populated (CVE-2014-8989).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SetgroupsPolicy { Allow, Deny }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum UserNsError {
    WrongKind, InitialOwner, NoParent, AlreadyPopulated, EmptyExtents, TooManyExtents,
    ZeroCount, RangeOverflow, Overlap, UnprivilegedNotOwnId, SetgroupsMustDenyFirst,
    SetgroupsLockedAfterGidMap,
}

impl From<ExtentError> for UserNsError {
    fn from(error: ExtentError) -> Self {
        match error {
            ExtentError::Empty => Self::EmptyExtents,
            ExtentError::TooMany => Self::TooManyExtents,
            ExtentError::ZeroCount => Self::ZeroCount,
            ExtentError::RangeOverflow => Self::RangeOverflow,
            ExtentError::Overlap => Self::Overlap,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct UserNsState {
    uid_map: Option<Vec<IdMapExtent>>,
    gid_map: Option<Vec<IdMapExtent>>,
    setgroups: SetgroupsPolicy,
}

impl Default for UserNsState {
    fn default() -> Self { Self { uid_map: None, gid_map: None, setgroups: SetgroupsPolicy::Allow } }
}

static STATE: sync::Spinlock<BTreeMap<NamespaceId, UserNsState>, sync::TaskList> =
    sync::Spinlock::new(BTreeMap::new());

fn owner_id(owner: &Namespace) -> Result<NamespaceId, UserNsError> {
    if owner.kind() != NamespaceKind::User { return Err(UserNsError::WrongKind); }
    Ok(owner.id())
}

/// Linux `if (!ns->parent) return -EPERM;` — the initial user namespace's
/// map is fixed at boot and never accepts a write. # C: O(1)
fn require_writable_owner(owner: &Namespace) -> Result<NamespaceId, UserNsError> {
    let id = owner_id(owner)?;
    if owner.is_initial() { return Err(UserNsError::InitialOwner); }
    if owner.parent().is_none() { return Err(UserNsError::NoParent); }
    Ok(id)
}

fn remove(kind: NamespaceKind, id: NamespaceId) {
    if kind == NamespaceKind::User { STATE.lock().remove(&id); }
}

/// Identity extent Linux seeds `init_user_ns`'s maps with at boot. # C: O(1)
fn initial_map() -> Vec<IdMapExtent> {
    let mut map = Vec::with_capacity(1);
    map.push(IdMapExtent { ns_id: INITIAL_NS_ID, host_id: INITIAL_HOST_ID, count: INITIAL_COUNT });
    map
}

fn map_field(state: &UserNsState, kind: IdMapKind) -> &Option<Vec<IdMapExtent>> {
    match kind { IdMapKind::Uid => &state.uid_map, IdMapKind::Gid => &state.gid_map }
}

fn map_field_mut(state: &mut UserNsState, kind: IdMapKind) -> &mut Option<Vec<IdMapExtent>> {
    match kind { IdMapKind::Uid => &mut state.uid_map, IdMapKind::Gid => &mut state.gid_map }
}

/// Snapshot the current map (empty when unset — Linux shows an empty
/// `uid_map`/`gid_map` file until the first successful write). The
/// immortal initial user namespace always reports the full-range identity
/// extent Linux seeds it with at boot, never empty. # C: O(log N + extents)
pub fn snapshot_map<H: core::ops::Deref<Target = Namespace>>(owner: &H, kind: IdMapKind)
    -> Result<Vec<IdMapExtent>, UserNsError>
{
    owner_id(owner)?;
    if owner.is_initial() { return Ok(initial_map()); }
    let states = STATE.lock();
    Ok(states.get(&owner.id()).and_then(|s| map_field(s, kind).clone()).unwrap_or_default())
}

/// Snapshot the current `setgroups` policy. The initial user namespace is
/// permanently `Allow` (Linux never exposes a deny path for it). # C: O(log N)
pub fn setgroups_policy<H: core::ops::Deref<Target = Namespace>>(owner: &H)
    -> Result<SetgroupsPolicy, UserNsError>
{
    owner_id(owner)?;
    if owner.is_initial() { return Ok(SetgroupsPolicy::Allow); }
    let states = STATE.lock();
    Ok(states.get(&owner.id()).map(|s| s.setgroups).unwrap_or(SetgroupsPolicy::Allow))
}

/// Apply one validated `uid_map`/`gid_map` write (Linux `map_write`).
///
/// `writer_has_cap_in_parent` is `CAP_SETUID`/`CAP_SETGID` held by the
/// writer in the target namespace's PARENT (the caller resolves this via
/// the capability/namespace-ancestry check — this crate stays
/// dependency-neutral over `core`+`alloc` and never look up a `Task`).
/// Without that capability, Linux restricts the write to a SINGLE extent
/// mapping exactly the writer's own effective id (`writer_own_id`) with
/// `count == 1`. `gid_map` additionally requires `setgroups == Deny`
/// first for that unprivileged path (CVE-2014-8989). Write-once: a second
/// write to an already-populated map is always `EPERM`, privileged or not.
/// # C: O(extents^2 + log N)
pub fn write_map(owner: &NamespaceRef, kind: IdMapKind, writer_has_cap_in_parent: bool,
    writer_own_id: u32, extents: &[IdMapExtent]) -> Result<(), UserNsError>
{
    let id = require_writable_owner(owner)?;
    validate_extents(extents)?;
    if !writer_has_cap_in_parent {
        let sole = extents[0];
        if extents.len() != 1 || sole.count != 1 || sole.host_id != writer_own_id {
            return Err(UserNsError::UnprivilegedNotOwnId);
        }
    }
    let mut states = STATE.lock();
    let state = states.entry(id).or_default();
    if map_field(state, kind).is_some() { return Err(UserNsError::AlreadyPopulated); }
    if kind == IdMapKind::Gid && !writer_has_cap_in_parent
        && state.setgroups != SetgroupsPolicy::Deny
    {
        return Err(UserNsError::SetgroupsMustDenyFirst);
    }
    *map_field_mut(state, kind) = Some(extents.to_vec());
    drop(states);
    owner.register_finalizer(remove);
    Ok(())
}

/// Apply one `/proc/<pid>/setgroups` write (Linux `proc_setgroups_write`).
/// Once `gid_map` is populated the policy is permanently locked — ANY
/// further write (including re-asserting the current value) is `EPERM`,
/// matching Linux `uid_gid_map_empty` gate rather than only blocking the
/// `Deny`->`Allow` direction. # C: O(log N)
pub fn write_setgroups(owner: &NamespaceRef, policy: SetgroupsPolicy) -> Result<(), UserNsError> {
    let id = require_writable_owner(owner)?;
    let mut states = STATE.lock();
    let state = states.entry(id).or_default();
    if state.gid_map.is_some() { return Err(UserNsError::SetgroupsLockedAfterGidMap); }
    state.setgroups = policy;
    drop(states);
    owner.register_finalizer(remove);
    Ok(())
}

#[cfg(test)]
pub(crate) fn contains(id: NamespaceId) -> bool { STATE.lock().contains_key(&id) }
