use alloc::{collections::VecDeque, string::String, sync::Arc, vec::Vec};

use sync::{Socket as UnixLockClass, Spinlock};

use sched;
use vfs;

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
    /// Connected peer path for AF_UNIX SOCK_DGRAM.
    pub peer: Spinlock<Option<String>, UnixLockClass>,
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
            peer: Spinlock::new(None),
            #[cfg(target_os = "oxide-kernel")]
            waiters: sched::live::WaitList::new(),
            subs: Spinlock::new(None),
        })
    }

    /// F181a: register owning InetSocket's subscribers.
    /// # C: O(1)
    pub fn register_subs(&self, subs: &Arc<vfs::PollSubscribers>) {
        *self.subs.lock() = Some(Arc::downgrade(subs));
    }

    /// Store the connected datagram peer.
    /// # C: O(N path)
    pub fn set_peer(&self, path: String) {
        *self.peer.lock() = Some(path);
    }

    /// Return the connected datagram peer, if any.
    /// # C: O(1)
    pub fn peer(&self) -> Option<String> {
        self.peer.lock().clone()
    }

    /// Push a complete dgram onto the queue.
    /// # C: O(1)
    pub fn push(&self, msg: UnixDgram) {
        self.msgs.lock().push_back(msg);
        #[cfg(target_os = "oxide-kernel")]
        {
            self.waiters.wake_all();
            // F181a: wake owning socket's epoll subscribers; fall
            // back to global broadcast if subs not yet registered.
            let slot = self.subs.lock().clone();
            if let Some(weak) = slot {
                if let Some(s) = weak.upgrade() {
                    s.notify();
                    return;
                }
            }
            sched::live::notify_epoll_waiters();
        }
    }

    /// Pop one dgram if any.
    /// # C: O(1)
    pub fn pop(&self) -> Option<UnixDgram> {
        self.msgs.lock().pop_front()
    }
}
