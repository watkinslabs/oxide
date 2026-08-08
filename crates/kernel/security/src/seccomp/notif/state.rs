// The listener's queue and its state machine: what a notification is, which
// transitions each ioctl is allowed to make, and what the notified task must
// do when it wakes. No locking, no task state, no user memory — the lock and
// the wait live in `listener.rs`, the copies in `ioctl.rs`.
//
// UNGATED (`CLAUDE.md` phantom-test rule): every rule below is a decision the
// hosted suite drives directly.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::seccomp::insn::SeccompData;
use super::uapi::*;

/// A notification's life. It only ever moves forwards.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NotifState {
    /// Queued; no supervisor has picked it up.
    Init,
    /// Handed to a supervisor by `NOTIF_RECV` and awaiting its reply.
    Sent,
    /// The supervisor replied, or the listener went away.
    Replied,
}

/// A descriptor the supervisor asked the notified task to install in itself.
/// The INSTALL is done by the notified task, in its own context, which is what
/// makes "put this descriptor in the target" need no cross-task fd table
/// writer.
pub struct AddFd {
    /// Identifies this request to the supervisor waiting on it.
    pub seq: u64,
    /// The supervisor's open file description being handed over.
    pub file: Arc<vfs::File>,
    /// `O_CLOEXEC` or nothing.
    pub newfd_flags: u32,
    /// The supervisor picked the descriptor number.
    pub setfd: bool,
    pub newfd: i32,
    /// Install AND reply in one step.
    pub send: bool,
}

/// One intercepted syscall waiting on a supervisor.
pub struct Knotif {
    pub id:    u64,
    /// The notified thread, by kernel tid. The number the supervisor is shown
    /// is derived at `NOTIF_RECV` from ITS namespace, never stored here.
    pub tid:   u32,
    pub data:  SeccompData,
    pub state: NotifState,
    pub val:   i64,
    pub error: i32,
    pub flags: u32,
    /// Descriptor injections queued for the notified task to perform.
    pub addfd: Vec<AddFd>,
}

impl Knotif {
    /// Whether the notified task has anything left to do or collect.
    /// # C: O(1)
    fn settled(&self) -> bool { self.state == NotifState::Replied && self.addfd.is_empty() }
}

/// A finished descriptor injection, waiting for the supervisor that asked for
/// it to collect the result.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AddFdResult {
    pub seq: u64,
    /// The descriptor number installed in the target, or a negative errno.
    pub ret: i64,
}

/// Everything behind the listener's lock.
pub struct Inner {
    /// `SECCOMP_IOCTL_NOTIF_SET_FLAGS`.
    pub flags: u64,
    /// The filter was installed with `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV`:
    /// once a supervisor has picked a notification up, only a fatal signal
    /// ends the notified task's wait.
    pub wait_killable_recv: bool,
    next_id:  u64,
    next_seq: u64,
    /// The listener fd is gone. Nothing new is queued and every waiter leaves.
    pub closed: bool,
    pub notifs: Vec<Knotif>,
    /// Completed injections, keyed by the sequence the requester holds.
    pub addfd_done: Vec<AddFdResult>,
}

impl Inner {
    /// # C: O(1)
    pub fn new(first_id: u64, wait_killable_recv: bool) -> Self {
        Self { flags: 0, wait_killable_recv, next_id: first_id, next_seq: 1,
               closed: false, notifs: Vec::new(), addfd_done: Vec::new() }
    }

    fn find(&mut self, id: u64) -> Option<&mut Knotif> {
        self.notifs.iter_mut().find(|n| n.id == id)
    }

    /// Queue an intercepted syscall. `None` once the listener is gone — the
    /// caller then takes the no-listener answer, exactly as if the filter had
    /// never had one.
    /// # C: O(1)
    pub fn queue(&mut self, tid: u32, data: SeccompData) -> Option<u64> {
        if self.closed { return None; }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.notifs.push(Knotif { id, tid, data, state: NotifState::Init,
                                  val: 0, error: 0, flags: 0, addfd: Vec::new() });
        Some(id)
    }

    /// Whether any notification is still waiting to be picked up.
    /// # C: O(N)
    pub fn has_pending(&self) -> bool {
        self.notifs.iter().any(|n| n.state == NotifState::Init)
    }

    /// `SECCOMP_IOCTL_NOTIF_RECV`: hand the oldest un-picked-up notification
    /// to the supervisor and mark it sent. `None` when there is none — the
    /// notified task may have been killed between the wake and the lock.
    /// # C: O(N)
    pub fn recv(&mut self) -> Option<(u64, u32, SeccompData)> {
        let n = self.notifs.iter_mut().find(|n| n.state == NotifState::Init)?;
        n.state = NotifState::Sent;
        Some((n.id, n.tid, n.data))
    }

    /// Undo a `recv` whose copy to the supervisor faulted, so the notification
    /// stays alive and another `RECV` can pick it up. It may have died while
    /// the lock was dropped, so a missing id is not an error.
    /// # C: O(N)
    pub fn recv_undo(&mut self, id: u64) {
        if let Some(n) = self.find(id) {
            if n.state == NotifState::Sent { n.state = NotifState::Init; }
        }
    }

    /// `SECCOMP_IOCTL_NOTIF_SEND`. Exactly one reply per notification: a
    /// second one is EINPROGRESS, and a reply to something never picked up is
    /// EINPROGRESS too — a supervisor may only answer what it was handed.
    /// # C: O(N)
    pub fn reply(&mut self, r: NotifResp) -> Result<(), Errno> {
        validate_resp(&r)?;
        let n = self.find(r.id).ok_or(Errno::Enoent)?;
        if n.state != NotifState::Sent { return Err(Errno::Einprogress); }
        n.state = NotifState::Replied;
        n.val = r.val;
        n.error = r.error;
        n.flags = r.flags;
        Ok(())
    }

    /// `SECCOMP_IOCTL_NOTIF_ID_VALID`: is this notification still outstanding
    /// AND already handed to a supervisor? Answering for one that has not been
    /// picked up would tell a supervisor its id is stale when it is not.
    /// # C: O(N)
    pub fn id_valid(&mut self, id: u64) -> Result<(), Errno> {
        match self.find(id) {
            Some(n) if n.state == NotifState::Sent => Ok(()),
            _ => Err(Errno::Enoent),
        }
    }

    /// `SECCOMP_IOCTL_NOTIF_SET_FLAGS`.
    /// # C: O(1)
    pub fn set_flags(&mut self, flags: u64) -> Result<(), Errno> {
        if flags & !USER_NOTIF_FD_SYNC_WAKE_UP != 0 { return Err(Errno::Einval); }
        self.flags = flags;
        Ok(())
    }

    /// `SECCOMP_IOCTL_NOTIF_ADDFD`: queue a descriptor for the notified task
    /// to install in itself. Returns the sequence to wait on.
    ///
    /// Injection is refused before the notification has been picked up and
    /// after it has been answered — in the first case the target has not been
    /// examined yet, in the second it is already leaving. Combining the
    /// injection with the reply is refused while other injections are still
    /// queued, because the reply would race them.
    /// # C: O(N)
    pub fn addfd_queue(&mut self, id: u64, file: Arc<vfs::File>, req: &AddfdReq)
        -> Result<u64, Errno>
    {
        let seq = self.next_seq;
        let n = self.find(id).ok_or(Errno::Enoent)?;
        if n.state != NotifState::Sent { return Err(Errno::Einprogress); }
        let send = req.flags & ADDFD_FLAG_SEND != 0;
        if send && !n.addfd.is_empty() { return Err(Errno::Ebusy); }
        if send { n.state = NotifState::Replied; }
        n.addfd.push(AddFd {
            seq, file, newfd_flags: req.newfd_flags,
            setfd: req.flags & ADDFD_FLAG_SETFD != 0, newfd: req.newfd as i32, send,
        });
        self.next_seq = self.next_seq.wrapping_add(1);
        Ok(seq)
    }

    /// Take the next injection the notified task must perform.
    /// # C: O(N)
    pub fn addfd_take(&mut self, id: u64) -> Option<AddFd> {
        let n = self.find(id)?;
        if n.addfd.is_empty() { None } else { Some(n.addfd.remove(0)) }
    }

    /// Publish an injection's outcome and fold it into the notification when
    /// the request also carried the reply. A failed atomic inject-and-reply
    /// puts the notification back in the supervisor's hands rather than
    /// completing the syscall with a descriptor that does not exist.
    /// # C: O(N)
    pub fn addfd_complete(&mut self, id: u64, a: &AddFd, ret: i64) {
        if a.send {
            if let Some(n) = self.find(id) {
                if ret < 0 { n.state = NotifState::Sent; }
                else { n.flags = 0; n.error = 0; n.val = ret; }
            }
        }
        self.addfd_done.push(AddFdResult { seq: a.seq, ret });
    }

    /// Collect an injection's outcome, if it has one yet.
    /// # C: O(N)
    pub fn addfd_collect(&mut self, seq: u64) -> Option<i64> {
        let i = self.addfd_done.iter().position(|r| r.seq == seq)?;
        Some(self.addfd_done.remove(i).ret)
    }

    /// Withdraw an injection the supervisor stopped waiting for. False when the
    /// notified task already took it, in which case its result is on the way.
    /// # C: O(N)
    pub fn addfd_cancel(&mut self, id: u64, seq: u64) -> bool {
        let Some(n) = self.find(id) else { return false };
        match n.addfd.iter().position(|a| a.seq == seq) {
            Some(i) => { n.addfd.remove(i); true }
            None => false,
        }
    }

    /// The notified task is leaving: every injection queued for it is answered
    /// ESRCH, because nothing will ever perform it.
    /// # C: O(N)
    pub fn addfd_abandon(&mut self, id: u64) {
        let Some(n) = self.find(id) else { return };
        let pending: Vec<u64> = n.addfd.drain(..).map(|a| a.seq).collect();
        let esrch = -(Errno::Esrch.as_i32() as i64);
        for seq in pending { self.addfd_done.push(AddFdResult { seq, ret: esrch }); }
    }

    /// The reply a notified task collects, once its notification is settled.
    /// # C: O(N)
    pub fn take_reply(&mut self, id: u64) -> Option<(i64, i32, u32)> {
        let i = self.notifs.iter().position(|n| n.id == id && n.settled())?;
        let n = self.notifs.remove(i);
        Some((n.val, n.error, n.flags))
    }

    /// Drop a notification whose task stopped waiting for it.
    /// # C: O(N)
    pub fn drop_notif(&mut self, id: u64) {
        if let Some(i) = self.notifs.iter().position(|n| n.id == id) { self.notifs.remove(i); }
    }

    /// Whether the notified task has anything to do the moment it wakes: a
    /// reply to collect, a descriptor to install, or a notification that is
    /// gone entirely.
    /// # C: O(N)
    pub fn actionable(&mut self, id: u64) -> bool {
        match self.find(id) {
            None => true,
            Some(n) => n.state == NotifState::Replied || !n.addfd.is_empty(),
        }
    }

    /// Whether an injection's outcome is waiting to be collected.
    /// # C: O(N)
    pub fn addfd_settled(&self, seq: u64) -> bool {
        self.addfd_done.iter().any(|r| r.seq == seq)
    }

    /// Whether the notified task should now sleep only for a fatal signal:
    /// the filter asked for it and a supervisor has the notification in hand.
    /// # C: O(N)
    pub fn sleep_killable(&mut self, id: u64) -> bool {
        if !self.wait_killable_recv { return false; }
        matches!(self.find(id), Some(n) if n.state != NotifState::Init)
    }

    /// The listener fd is gone. Every unanswered notification is released with
    /// the answer a filter with no listener gives, so no task waits forever on
    /// a supervisor that cannot come back.
    /// # C: O(N)
    pub fn detach(&mut self) {
        self.closed = true;
        let enosys = -(Errno::Enosys.as_i32() as i32);
        for n in self.notifs.iter_mut() {
            if n.state == NotifState::Replied { continue; }
            n.state = NotifState::Replied;
            n.error = enosys;
            n.val = 0;
            n.flags = 0;
        }
    }

    /// Readiness of the listener fd. Readable while a notification waits to be
    /// picked up, writable while one waits for its reply, and hung up once
    /// nothing can ever arrive again.
    /// # C: O(N)
    pub fn poll_mask(&self, users: bool) -> u32 {
        let mut m = 0;
        for n in self.notifs.iter() {
            match n.state {
                NotifState::Init => m |= vfs::POLL_IN,
                NotifState::Sent => m |= vfs::POLL_OUT,
                NotifState::Replied => {}
            }
        }
        if !users { m |= vfs::POLL_HUP; }
        m
    }
}

/// `struct seccomp_notif_resp` admission. Asking for the syscall to run while
/// also naming a return value is refused rather than silently resolved: the
/// two answers contradict each other.
/// # C: O(1)
pub fn validate_resp(r: &NotifResp) -> Result<(), Errno> {
    if r.flags & !USER_NOTIF_FLAG_CONTINUE != 0 { return Err(Errno::Einval); }
    if r.flags & USER_NOTIF_FLAG_CONTINUE != 0 && (r.error != 0 || r.val != 0) {
        return Err(Errno::Einval);
    }
    Ok(())
}

/// `struct seccomp_notif_addfd` admission, before the source descriptor is
/// resolved. An injected descriptor may only carry `O_CLOEXEC`, and naming a
/// target number without asking to choose it is a contradiction.
/// # C: O(1)
pub fn validate_addfd(a: &AddfdReq) -> Result<(), Errno> {
    if a.newfd_flags & !O_CLOEXEC != 0 { return Err(Errno::Einval); }
    if a.flags & !ADDFD_FLAG_MASK != 0 { return Err(Errno::Einval); }
    if a.newfd != 0 && a.flags & ADDFD_FLAG_SETFD == 0 { return Err(Errno::Einval); }
    if a.newfd > i32::MAX as u32 { return Err(Errno::Einval); }
    Ok(())
}

/// Size admission for the extensible-argument `ADDFD` command.
/// # C: O(1)
pub fn validate_addfd_size(size: u32) -> Result<(), Errno> {
    if size < ADDFD_SIZE_VER0 || size >= ADDFD_SIZE_MAX { return Err(Errno::Einval); }
    Ok(())
}

/// What a notified task does with a settled notification.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// `SECCOMP_USER_NOTIF_FLAG_CONTINUE`: dispatch the syscall after all.
    Continue,
    /// Skip the syscall and hand this value back.
    Skip(i64),
}

/// The reply, as the notified task's syscall return. The error member wins
/// when it is set; otherwise the value does.
/// # C: O(1)
pub fn outcome(val: i64, error: i32, flags: u32) -> Outcome {
    if flags & USER_NOTIF_FLAG_CONTINUE != 0 { return Outcome::Continue; }
    if error != 0 { Outcome::Skip(error as i64) } else { Outcome::Skip(val) }
}

#[cfg(test)]
#[path = "tests/state.rs"]
mod tests;
