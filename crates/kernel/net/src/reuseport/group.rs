// The reuseport group object itself: one program slot shared by every member
// of a bind key, plus the member bookkeeping the detach ladder branches on.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use sync::{Socket as SockLockClass, Spinlock};
use syscall::errno::Errno;

use super::slot::SlotCell;
use crate::bpf_filter::FilterProgram;

/// One SO_REUSEPORT bind key's shared selection state.
pub struct ReuseportGroup {
    prog: Spinlock<Option<Arc<FilterProgram>>, SockLockClass>,
    /// Members are held weakly through their own `sk_reuseport_cb` cells, so a
    /// closed socket leaves the group when its cell is dropped.
    members: Spinlock<Vec<Weak<SlotCell>>, SockLockClass>,
    has_conns: AtomicBool,
    closed_socks: AtomicUsize,
}

impl ReuseportGroup {
    /// Build an empty group with no program and no members. # C: O(1)
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            prog: Spinlock::new(None),
            members: Spinlock::new(Vec::new()),
            has_conns: AtomicBool::new(false),
            closed_socks: AtomicUsize::new(0),
        })
    }

    /// Replace the selection program; a previous program is released. # C: O(1)
    pub fn attach_prog(&self, prog: FilterProgram) {
        *self.prog.lock() = Some(Arc::new(prog));
    }

    /// Drop the selection program, distinguishing an absent one. # C: O(1)
    pub fn detach_prog(&self) -> Result<(), Errno> {
        let mut slot = self.prog.lock();
        if slot.is_none() { return Err(Errno::Enoent); }
        *slot = None;
        Ok(())
    }

    /// Observe whether a selection program is installed. # C: O(1)
    pub fn has_prog(&self) -> bool { self.prog.lock().is_some() }

    /// Run the selection program and map its result onto a member index.
    ///
    /// The program's return value is the index Linux uses directly; a result at
    /// or past the member count, an empty member set, and an absent program all
    /// select nothing, leaving the caller on its flow-hash distribution. A
    /// delivery path holding the received bytes supplies them as the program
    /// input; a path holding only the flow identity supplies the hash itself.
    /// # C: O(program)
    pub fn select(&self, hash: u32, members_len: usize, packet: &[u8]) -> Option<usize> {
        if members_len == 0 { return None; }
        let prog = self.prog.lock().clone()?;
        let hash_bytes = hash.to_be_bytes();
        let input = if packet.is_empty() { &hash_bytes[..] } else { packet };
        let index = crate::bpf_filter::run_program(&prog, input) as usize;
        (index < members_len).then_some(index)
    }

    /// Register one member cell. # C: O(N members)
    pub fn add_member(&self, member: &Arc<SlotCell>) {
        let mut members = self.members.lock();
        members.retain(|weak| weak.strong_count() != 0);
        if members.iter().any(|weak| weak.as_ptr() == Arc::as_ptr(member)) { return; }
        members.push(Arc::downgrade(member));
    }

    /// Remove one member cell. # C: O(N members)
    pub fn remove_member(&self, member: &Arc<SlotCell>) {
        let mut members = self.members.lock();
        members.retain(|weak| weak.strong_count() != 0 && weak.as_ptr() != Arc::as_ptr(member));
    }

    /// Live member count after dropping departed sockets. # C: O(N members)
    pub fn num_socks(&self) -> usize {
        let mut members = self.members.lock();
        members.retain(|weak| weak.strong_count() != 0);
        members.len()
    }

    /// Members retained past their socket's shutdown. # C: O(1)
    pub fn num_closed_socks(&self) -> usize { self.closed_socks.load(Ordering::Acquire) }

    /// Record one member kept after shutdown removed it from its bind key. # C: O(1)
    pub fn note_closed_sock(&self) { self.closed_socks.fetch_add(1, Ordering::AcqRel); }

    /// Release one shutdown member's retained slot. # C: O(1)
    pub fn release_closed_sock(&self) {
        let _ = self.closed_socks.fetch_update(Ordering::AcqRel, Ordering::Acquire,
            |used| used.checked_sub(1));
    }

    /// Whether any member has taken a connected peer. # C: O(1)
    pub fn has_conns(&self) -> bool { self.has_conns.load(Ordering::Acquire) }

    /// Latch that a member connected, which pins established flows. # C: O(1)
    pub fn set_has_conns(&self) { self.has_conns.store(true, Ordering::Release); }
}
