// The listener object a `SECCOMP_FILTER_FLAG_NEW_LISTENER` install creates:
// the queue, the wait queue every side of the protocol sleeps on, and the
// registry that maps a filter's recorded listener id onto it.
//
// The id, not the object, is what an installed filter carries: a filter is
// copied by value onto every thread a `TSYNC` reaches and every child a
// `fork` creates, and all of those copies must reach the SAME listener. The
// registry is the single owner; a filter holding a stale id finds nothing and
// takes the no-listener answer, which is exactly what a closed listener means.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use sync::{Spinlock, TaskList as ListenerClass};
use vfs::PollSubscribers;

use super::state::Inner;
use super::wait::WaitList;

/// Listener identity, as recorded on the filter that owns it. Never reused.
static NEXT_LISTENER_ID: AtomicU64 = AtomicU64::new(1);
/// Notification identity, drawn from one space across every listener so an id
/// is unique for the life of the boot. A notification is only ever reachable
/// through the listener fd that produced it.
static NEXT_NOTIF_ID: AtomicU64 = AtomicU64::new(1);

/// One supervisor channel.
pub struct Listener {
    pub id: u64,
    pub inner: Spinlock<Inner, ListenerClass>,
    /// Every side sleeps here: notified tasks awaiting a reply, supervisors
    /// awaiting a notification, supervisors awaiting an injection result. A
    /// state change wakes them all and each re-tests its own condition, which
    /// is what keeps the three protocols from needing three queues that could
    /// disagree about who has been woken.
    pub wq: WaitList,
    pub poll_subs: Arc<PollSubscribers>,
}

impl Listener {
    /// # C: O(1)
    pub fn new(wait_killable_recv: bool) -> Arc<Self> {
        let first = NEXT_NOTIF_ID.fetch_add(NOTIF_ID_STRIDE, Ordering::AcqRel);
        Arc::new(Self {
            id: NEXT_LISTENER_ID.fetch_add(1, Ordering::AcqRel),
            inner: Spinlock::new(Inner::new(first, wait_killable_recv)),
            wq: WaitList::new(),
            poll_subs: Arc::new(PollSubscribers::new()),
        })
    }

    /// Wake everything parked on this listener and every `epoll` watching it.
    /// # C: O(N_waiters)
    pub fn wake(&self) {
        self.wq.wake_all();
        self.poll_subs.notify();
    }
}

/// Notification ids a single listener may issue before it would collide with
/// the next listener's space. A listener that outruns it wraps into the shared
/// space and the queue's own id search still distinguishes live entries.
const NOTIF_ID_STRIDE: u64 = 1 << 20;

/// id -> listener. Entries live from the install that created the listener to
/// the last close of its fd.
static LISTENERS: Spinlock<Vec<(u64, Arc<Listener>)>, ListenerClass>
    = Spinlock::new(Vec::new());

/// Publish a new listener and return it with its id.
/// # C: O(1)
pub fn create(wait_killable_recv: bool) -> Arc<Listener> {
    let l = Listener::new(wait_killable_recv);
    LISTENERS.lock().push((l.id, l.clone()));
    l
}

/// Resolve a filter's recorded listener id. `None` once the listener fd is
/// gone — the filter then behaves as one that never had a listener.
/// # C: O(N_listeners)
pub fn lookup(id: u64) -> Option<Arc<Listener>> {
    LISTENERS.lock().iter().find(|(i, _)| *i == id).map(|(_, l)| l.clone())
}

/// Last close of a listener fd: release every task waiting on a supervisor
/// that can no longer answer, then drop the registry's reference so the id
/// resolves to nothing.
/// # C: O(N_listeners + N_notifications)
pub fn detach(l: &Arc<Listener>) {
    l.inner.lock().detach();
    let mut g = LISTENERS.lock();
    if let Some(i) = g.iter().position(|(id, _)| *id == l.id) { g.remove(i); }
    drop(g);
    l.wake();
}

/// Whether any live task still runs a filter that names this listener —
/// Linux's filter user count, derived rather than stored so it cannot drift
/// from the chains that are the truth.
/// # C: O(N_tasks x N_filters)
pub fn has_users(id: u64) -> bool {
    #[cfg(target_os = "oxide-kernel")]
    {
        for tid in sched::registry::live_tids() {
            let Some(t) = sched::registry::lookup(tid) else { continue };
            if t.seccomp_filters.lock().iter().any(|f| f.listener == Some(id)) { return true; }
        }
        false
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    { let _ = id; false }
}

#[cfg(test)]
#[path = "tests/listener.rs"]
mod tests;
