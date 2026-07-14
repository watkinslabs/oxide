use alloc::{collections::VecDeque, sync::Arc, vec::Vec};

use sync::{Socket as UnixLockClass, Spinlock};

use sched;
use vfs;

use super::UnixAddr;

pub struct UnixDgram {
    pub payload: Vec<u8>,
    /// Sender's (pid, uid, gid) at sendmsg time.
    pub creds: (u32, u32, u32),
    /// F189: SCM_RIGHTS — files carried alongside the payload.
    #[cfg(target_os = "oxide-kernel")]
    pub fds: Vec<Arc<vfs::File>>,
    /// Hosted-test stub for the same slot.
    #[cfg(not(target_os = "oxide-kernel"))]
    pub fds: Vec<u32>,
}

pub struct UnixDgramQueue {
    pub msgs: Spinlock<VecDeque<UnixDgram>, UnixLockClass>,
    /// Bound local address for pathname/abstract datagram sockets.
    pub bound: Spinlock<Option<UnixAddr>, UnixLockClass>,
    /// Connected peer address for AF_UNIX SOCK_DGRAM.
    pub peer: Spinlock<Option<UnixAddr>, UnixLockClass>,
    pub reader_shutdown: core::sync::atomic::AtomicBool,
    released: core::sync::atomic::AtomicBool,
    #[cfg(target_os = "oxide-kernel")]
    pub waiters: sched::live::WaitList,
    /// F181a: epoll subscribers of the owning InetSocket.
    pub subs: Spinlock<Option<alloc::sync::Weak<vfs::PollSubscribers>>, UnixLockClass>,
}

impl UnixDgramQueue {
    /// # C: O(1)
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            msgs: Spinlock::new(VecDeque::new()),
            bound: Spinlock::new(None),
            peer: Spinlock::new(None),
            reader_shutdown: core::sync::atomic::AtomicBool::new(false),
            released: core::sync::atomic::AtomicBool::new(false),
            #[cfg(target_os = "oxide-kernel")]
            waiters: sched::live::WaitList::new(),
            subs: Spinlock::new(None),
        })
    }

    /// Store the local bind address.
    /// # C: O(1)
    pub fn set_bound(&self, addr: UnixAddr) {
        *self.bound.lock() = Some(addr);
    }

    /// Return the local bind address, if any.
    /// # C: O(1)
    pub fn bound(&self) -> Option<UnixAddr> {
        self.bound.lock().clone()
    }

    /// F181a: register owning InetSocket's subscribers.
    /// # C: O(1)
    pub fn register_subs(&self, subs: &Arc<vfs::PollSubscribers>) {
        *self.subs.lock() = Some(Arc::downgrade(subs));
    }

    /// Store the connected datagram peer.
    /// # C: O(1)
    pub fn set_peer(&self, addr: UnixAddr) {
        *self.peer.lock() = Some(addr);
    }

    /// Clear the connected datagram peer. # C: O(1)
    pub fn clear_peer(&self) {
        *self.peer.lock() = None;
    }

    /// Return the connected datagram peer, if any.
    /// # C: O(1)
    pub fn peer(&self) -> Option<UnixAddr> {
        self.peer.lock().clone()
    }

    /// Enqueue unless the owning socket shut down its receive half.
    /// # C: O(1)
    pub fn try_push(&self, msg: UnixDgram) -> Result<(), crate::NetError> {
        let mut q = self.msgs.lock();
        if self.released.load(core::sync::atomic::Ordering::Acquire) { return Err(crate::NetError::Econnrefused); }
        if self.reader_shutdown.load(core::sync::atomic::Ordering::Acquire) { return Err(crate::NetError::Epipe); }
        q.push_back(msg);
        drop(q);
        #[cfg(target_os = "oxide-kernel")]
        {
            self.waiters.wake_all();
            if let Some(subs) = self.subs.lock().as_ref().and_then(|weak| weak.upgrade()) {
                subs.notify_mask(vfs::POLL_IN);
            } else { sched::live::notify_epoll_waiters(); }
        }
        Ok(())
    }

    /// Preserve queued datagrams, then expose EOF and reject later sends.
    /// # C: O(1)
    pub fn shutdown_reader(&self) {
        let q = self.msgs.lock();
        self.reader_shutdown.store(true, core::sync::atomic::Ordering::Release);
        drop(q);
        #[cfg(target_os = "oxide-kernel")]
        self.waiters.wake_all();
    }

    /// Close the queue at final fput and release all unread messages.
    /// # C: O(unread messages + descriptors)
    pub fn release(&self) {
        let dropped = {
            let mut q = self.msgs.lock();
            self.released.store(true, core::sync::atomic::Ordering::Release);
            self.reader_shutdown.store(true, core::sync::atomic::Ordering::Release);
            core::mem::take(&mut *q)
        };
        drop(dropped);
        #[cfg(target_os = "oxide-kernel")]
        self.waiters.wake_all();
    }

    /// Pop one dgram if any.
    /// # C: O(1)
    pub fn pop(&self) -> Option<UnixDgram> {
        self.msgs.lock().pop_front()
    }
}
