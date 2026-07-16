use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use super::{ConnKey, Listener, VsockConn, VsockOwner, VsockState, VsockTable};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcceptWait {
    Ready,
    Removed,
    Armed,
}

fn ready(c: &Arc<VsockConn>) -> bool {
    c.accept_ready.load(Ordering::Acquire)
}

impl VsockTable {
    /// Insert an inbound child while keeping it hidden from accept. # C: O(N)
    pub fn publish_accept(&self, owner: VsockOwner, port: u32, c: Arc<VsockConn>) -> bool {
        let listeners = self.listeners.lock();
        let listener = listeners.iter().find(|l| l.owner == Some(owner) && l.local_port == port)
            .or_else(|| listeners.iter().find(|l| l.owner.is_none() && l.local_port == port));
        let Some(listener) = listener else { return false; };
        c.bpf_filter.inherit_from(&listener.bpf_filter);
        let mut conns = self.conns.lock();
        if conns.iter().any(|old| old.key() == c.key()) { return false; }
        if listener.backlog.lock().len() >= listener.backlog_cap.load(Ordering::Acquire) { return false; }
        conns.push(c.clone());
        listener.backlog.lock().push_back(c);
        true
    }

    /// Make an exact inbound child accept-visible after response TX. # C: O(N)
    pub fn complete_accept(&self, c: &Arc<VsockConn>) -> bool {
        let listeners = self.listeners.lock();
        let listener = listeners.iter().find(|listener|
            listener.backlog.lock().iter().any(|child| Arc::ptr_eq(child, c)));
        let Some(listener) = listener.cloned() else { return false; };
        drop(listeners);
        if *c.st.lock() != VsockState::Connected { return false; }
        c.accept_ready.store(true, Ordering::Release);
        listener.notify_poll(vfs::POLL_IN);
        #[cfg(target_os = "oxide-kernel")]
        listener.accept_waiters.wake_all();
        true
    }

    /// Remove an exact response-pending child from backlog and table. # C: O(N)
    pub fn rollback_accept(&self, c: &Arc<VsockConn>) -> bool {
        let listeners = self.listeners.lock();
        let mut conns = self.conns.lock();
        let mut changed = alloc::vec::Vec::new();
        let mut removed = false;
        for listener in listeners.iter() {
            let mut backlog = listener.backlog.lock();
            let before = backlog.len();
            backlog.retain(|child| !Arc::ptr_eq(child, c));
            if backlog.len() != before {
                removed = true;
                changed.push(listener.clone());
            }
        }
        if !removed { return false; }
        conns.retain(|child| !Arc::ptr_eq(child, c));
        drop(conns);
        drop(listeners);
        *c.st.lock() = VsockState::Closed;
        for listener in changed { listener.notify_poll(vfs::POLL_IN); }
        true
    }

    /// Test helper: queue an existing child as response-complete. # C: O(N)
    #[cfg(test)]
    pub fn queue_accept(&self, owner: VsockOwner, port: u32, k: ConnKey) {
        let Some(c) = self.find(k) else { return; };
        c.accept_ready.store(true, Ordering::Release);
        let listeners = self.listeners.lock();
        let listener = listeners.iter().find(|l| l.owner == Some(owner) && l.local_port == port)
            .or_else(|| listeners.iter().find(|l| l.owner.is_none() && l.local_port == port));
        if let Some(listener) = listener { listener.backlog.lock().push_back(c); }
    }

    /// Pop one response-complete child from `port`. # C: O(N)
    pub fn pop_accept(&self, owner: Option<VsockOwner>, port: u32) -> Option<Arc<VsockConn>> {
        let (listener, child) = {
            let listeners = self.listeners.lock();
            let listener = listeners.iter().find(|l| l.owner == owner && l.local_port == port)?;
            let mut backlog = listener.backlog.lock();
            if !backlog.front().map(ready).unwrap_or(false) { return None; }
            let child = backlog.pop_front();
            (listener.clone(), child)
        };
        listener.notify_poll(vfs::POLL_IN);
        child
    }

    /// Pop from one exact listener only after response completion. # C: O(N)
    pub fn pop_accept_exact(&self, listener: &Arc<Listener>) -> Option<Arc<VsockConn>> {
        let (current, child) = {
            let listeners = self.listeners.lock();
            let current = listeners.iter().find(|l| Arc::ptr_eq(l, listener))?;
            let mut backlog = current.backlog.lock();
            if !backlog.front().map(ready).unwrap_or(false) { return None; }
            let child = backlog.pop_front();
            (current.clone(), child)
        };
        current.notify_poll(vfs::POLL_IN);
        child
    }

    /// True iff an exact listener's front child completed response TX. # C: O(N)
    pub fn pop_accept_peek_exact(&self, listener: &Arc<Listener>) -> bool {
        let listeners = self.listeners.lock();
        listeners.iter().find(|l| Arc::ptr_eq(l, listener))
            .and_then(|l| l.backlog.lock().front().cloned()).map(|c| ready(&c)).unwrap_or(false)
    }

    /// True iff `port` has a response-complete front child. # C: O(N)
    pub fn pop_accept_peek(&self, owner: Option<VsockOwner>, port: u32) -> bool {
        let listeners = self.listeners.lock();
        listeners.iter().find(|l| l.owner == owner && l.local_port == port)
            .and_then(|l| l.backlog.lock().front().cloned()).map(|c| ready(&c)).unwrap_or(false)
    }

    fn arm_accept_wait_exact_with(&self, listener: &Arc<Listener>, arm: impl FnOnce())
        -> AcceptWait
    {
        let listeners = self.listeners.lock();
        let Some(current) = listeners.iter().find(|current| Arc::ptr_eq(current, listener)) else {
            return AcceptWait::Removed;
        };
        let backlog = current.backlog.lock();
        if backlog.front().map(ready).unwrap_or(false) { return AcceptWait::Ready; }
        arm();
        drop(backlog);
        drop(listeners);
        AcceptWait::Armed
    }

    /// Atomically recheck one exact listener and arm an interruptible acceptor. # C: O(N)
    #[cfg(target_os = "oxide-kernel")]
    pub fn arm_accept_wait_exact(&self, listener: &Arc<Listener>, deadline_ns: u64) -> AcceptWait {
        self.arm_accept_wait_exact_with(listener, || {
            // SAFETY: registry and backlog locks serialize removal/enqueue with registration.
            unsafe { listener.accept_waiters.park_interruptible_with_deadline(deadline_ns); }
        })
    }

    /// Hosted observation of the canonical exact-listener wait gate. # C: O(N)
    #[cfg(not(target_os = "oxide-kernel"))]
    pub fn accept_wait_would_park_exact(&self, listener: &Arc<Listener>) -> AcceptWait {
        self.arm_accept_wait_exact_with(listener, || {})
    }
}
