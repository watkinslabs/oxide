// `BPF_MAP_TYPE_REUSEPORT_SOCKARRAY`: the map a reuseport selection program
// names one member of its own bind key through.
//
// Object lifetime is the whole problem this map has. A slot must not keep a
// socket alive — a map is not a bind, and a socket userspace closed has to
// stop receiving — yet a program may name a slot at any moment, including the
// moment after that close. So a slot holds a WEAK reference to the hashed
// transport object and nothing else: an upgrade that fails is an empty slot,
// answered with `ENOENT`, and the strong reference stays where it already is,
// in the bind table, which is the one registry that decides whether a socket
// is reachable at all. There is no second liveness state to disagree with it.
//
// The socket's own group, protocol and family are read at helper time and
// never cached at update time: a socket may leave or join a group after being
// stored, and a stale copy would let a program steer a packet to a member of a
// different bind key.
//
// No target gate: every decision here is hosted-testable (`docs/53§4`).

extern crate alloc;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicPtr, Ordering};

use syscall::errno::Errno;

/// The hashed transport object a slot names, type-erased: the network stack
/// owns what it actually is, and this map only has to hold it and hand it
/// back. Cloning is cheap and never resurrects a closed socket.
pub type HashedSock = Weak<dyn Any + Send + Sync>;

/// One stored socket, as the map holds it.
#[derive(Clone)]
pub struct SockHandle {
    /// Weakly held, so a slot stops answering for a socket the moment the
    /// bind table lets go of it.
    pub hashed: HashedSock,
    /// The socket's reuseport cell, held the same way and separately. Reading
    /// which group a socket is in must NOT take a reference to the socket
    /// itself: a selection runs in softirq, and being the last owner of a
    /// closing socket there would run its whole teardown from inside a program
    /// run. This cell's own teardown is a group and nothing else.
    pub cell: HashedSock,
    /// The socket cookie a syscall-side lookup reports.
    pub cookie: u64,
    /// `sk_protocol`. Fixed for the socket's whole life, so caching it costs
    /// no accuracy and saves touching the socket during a selection.
    pub protocol: u8,
    /// `sk_family`. Fixed for the socket's whole life, likewise.
    pub family: u16,
}

impl SockHandle {
    /// Whether the socket is still hashed. # C: O(1)
    pub fn is_live(&self) -> bool { self.hashed.strong_count() != 0 }

    /// Take a strong reference for the caller that will identify it. # C: O(1)
    pub fn upgrade(&self) -> Option<Arc<dyn Any + Send + Sync>> { self.hashed.upgrade() }
}

/// What a stored socket is right now, in the three terms the selection checks
/// are written in. Only the group can change while a socket is stored; the
/// other two ride the handle.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SockState {
    /// Identity of the SO_REUSEPORT group the socket currently belongs to.
    pub group_id: u64,
    /// `sk_protocol`, e.g. `IPPROTO_TCP`.
    pub protocol: u8,
    /// `sk_family`, e.g. `AF_INET`.
    pub family: u16,
}

/// The group running a selection program, in the same three terms.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RunnerState {
    pub group_id: u64,
    pub protocol: u8,
    pub family: u16,
}

/// Whether a named socket may be selected, and if not, why.
///
/// A socket that has closed and a socket that belongs to no group at all are
/// indistinguishable to a program and answer alike with `ENOENT`. A socket
/// that IS in a group, but not the group running the program, is reported by
/// whatever differs first: `EPROTOTYPE` for a different transport protocol,
/// `EAFNOSUPPORT` for a different address family, and `EBADFD` for a socket
/// that matches both and is therefore bound somewhere else.
/// # C: O(1)
pub fn select_check(runner: RunnerState, selected: Option<SockState>) -> Result<(), Errno> {
    let Some(selected) = selected else { return Err(Errno::Enoent); };
    if selected.group_id == runner.group_id { return Ok(()); }
    if selected.protocol != runner.protocol { return Err(Errno::Eprototype); }
    if selected.family != runner.family { return Err(Errno::Eafnosupport); }
    Err(Errno::Ebadfd)
}

/// Create-time field validation: the value is a socket descriptor, in either
/// of the two widths this map type accepts, and the key is an array index.
/// # C: O(1)
pub fn alloc_check(key_size: u32, value_size: u32, max_entries: u32, map_flags: u32)
    -> Result<(), Errno>
{
    if value_size != 4 && value_size != 8 { return Err(Errno::Einval); }
    if map_flags & !super::super::uapi::map_flags::ARRAY_CREATE_MASK != 0
        || key_size != 4 || max_entries == 0 {
        return Err(Errno::Einval);
    }
    Ok(())
}

/// Update-time flag arbitration, which is decided before the socket is even
/// looked at. # C: O(1)
pub fn update_flags_check(occupied: bool, flags: u64) -> Result<(), Errno> {
    use super::super::uapi::elem_flags as e;
    if flags > e::EXIST { return Err(Errno::Einval); }
    if occupied && flags == e::NOEXIST { return Err(Errno::Eexist); }
    if !occupied && flags == e::EXIST { return Err(Errno::Enoent); }
    Ok(())
}

/// The shape a socket must have to be stored at all.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct StoredShape {
    pub tcp_or_udp: bool,
    pub inet: bool,
    pub stream_or_dgram: bool,
    /// Already listening, or already bound: occupying a transport hash is
    /// what makes a socket reachable by an arriving packet at all.
    pub hashed: bool,
    /// Already a member of a SO_REUSEPORT group.
    pub in_group: bool,
}

/// Update-time socket validation. A socket of the wrong transport, family or
/// type is `ENOTSUPP` — a distinct value from `EOPNOTSUPP`. A socket of the
/// right shape that is not yet hashed, or belongs to no group, is `EINVAL`:
/// a program naming it could steer nothing, because no packet can reach it
/// and there is no group its membership could be compared against.
/// # C: O(1)
pub fn stored_shape_check(shape: StoredShape) -> Result<(), Errno> {
    if !shape.tcp_or_udp || !shape.inet || !shape.stream_or_dgram {
        return Err(Errno::Enotsupp);
    }
    if !shape.hashed || !shape.in_group { return Err(Errno::Einval); }
    Ok(())
}

/// The index one key names. Past the end is `E2big`, which is distinct from
/// the `ENOENT` of an empty slot inside the array. # C: O(1)
pub fn index_of(key: &[u8], max_entries: u32) -> Result<usize, Errno> {
    let raw: [u8; 4] = key.try_into().map_err(|_| Errno::Einval)?;
    let index = u32::from_ne_bytes(raw);
    if index >= max_entries { return Err(Errno::E2big); }
    Ok(index as usize)
}

/// The socket-array backing itself.
pub struct SockArray {
    slots: sync::Spinlock<Vec<Option<SockHandle>>, sync::TaskList>,
}

impl SockArray {
    /// Allocate `max_entries` empty slots. # C: O(max_entries)
    pub fn allocate(max_entries: u32) -> Result<Self, Errno> {
        let mut slots = Vec::new();
        slots.try_reserve_exact(max_entries as usize).map_err(|_| Errno::Enomem)?;
        slots.resize(max_entries as usize, None);
        Ok(Self { slots: sync::Spinlock::new(slots) })
    }

    /// The live socket a key names, releasing a slot whose socket has closed
    /// so the array stops holding a handle that can never answer again.
    /// # C: O(1)
    pub fn lookup(&self, key: &[u8], max_entries: u32) -> Result<Option<SockHandle>, Errno> {
        let index = index_of(key, max_entries)?;
        let mut slots = self.slots.lock();
        let slot = slots.get_mut(index).ok_or(Errno::E2big)?;
        if slot.as_ref().is_some_and(|handle| !handle.is_live()) { *slot = None; }
        Ok(slot.clone())
    }

    /// Install one socket, arbitrating `BPF_NOEXIST` / `BPF_EXIST` against the
    /// slot's LIVE occupancy — a slot holding a closed socket counts as empty,
    /// which is the same thing a lookup of it reports. # C: O(1)
    pub fn update(&self, key: &[u8], max_entries: u32, handle: SockHandle, flags: u64)
        -> Result<(), Errno>
    {
        let index = index_of(key, max_entries)?;
        let mut slots = self.slots.lock();
        let slot = slots.get_mut(index).ok_or(Errno::E2big)?;
        let occupied = slot.as_ref().is_some_and(|held| held.is_live());
        update_flags_check(occupied, flags)?;
        *slot = Some(handle);
        Ok(())
    }

    /// Clear one slot. A slot that held a socket which has already closed is
    /// `ENOENT`, the same answer an empty slot gives. # C: O(1)
    pub fn delete(&self, key: &[u8], max_entries: u32) -> Result<(), Errno> {
        let index = index_of(key, max_entries)?;
        let mut slots = self.slots.lock();
        let slot = slots.get_mut(index).ok_or(Errno::E2big)?;
        let live = slot.as_ref().is_some_and(|held| held.is_live());
        *slot = None;
        if live { Ok(()) } else { Err(Errno::Enoent) }
    }

    /// Iteration successor over slot indexes, occupied or not: an array's key
    /// space is its shape, not its contents. # C: O(1)
    pub fn next_key(&self, key: Option<&[u8]>, max_entries: u32)
        -> Result<Option<Vec<u8>>, Errno>
    {
        let next = match key {
            None => 0,
            Some(key) => index_of(key, max_entries)? + 1,
        };
        if next >= max_entries as usize { return Ok(None); }
        Ok(Some((next as u32).to_ne_bytes().to_vec()))
    }
}

/// Resolve one socket descriptor into the handle a sockarray stores. Installed
/// by the network stack, which is the only owner of what a socket is.
pub type SockFromFdFn = fn(i32) -> Result<SockHandle, Errno>;
/// Read a stored socket's current group, protocol and family. Installed by the
/// same owner.
pub type SockStateFn = fn(&SockHandle) -> Option<SockState>;

static FROM_FD: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
static STATE_OF: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Publish the network stack's socket resolvers. Idempotent. # C: O(1)
pub fn install_sock_resolvers(from_fd: SockFromFdFn, state_of: SockStateFn) {
    FROM_FD.store(from_fd as *mut (), Ordering::Release);
    STATE_OF.store(state_of as *mut (), Ordering::Release);
}

/// Resolve a descriptor to a storable socket. A kernel with no network stack
/// installed has no socket any descriptor could name. # C: O(1)
pub fn sock_from_fd(fd: i32) -> Result<SockHandle, Errno> {
    let raw = FROM_FD.load(Ordering::Acquire);
    if raw.is_null() { return Err(Errno::Einval); }
    // SAFETY: install_sock_resolvers stores only this exact function signature.
    let f: SockFromFdFn = unsafe { core::mem::transmute(raw) };
    f(fd)
}

/// Read a stored socket's live state. # C: O(1)
pub fn sock_state(handle: &SockHandle) -> Option<SockState> {
    let raw = STATE_OF.load(Ordering::Acquire);
    if raw.is_null() { return None; }
    // SAFETY: install_sock_resolvers stores only this exact function signature.
    let f: SockStateFn = unsafe { core::mem::transmute(raw) };
    f(handle)
}

#[cfg(test)]
#[path = "sockarray_tests.rs"]
mod tests;
