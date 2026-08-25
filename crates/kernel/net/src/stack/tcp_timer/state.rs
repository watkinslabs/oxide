use super::*;

/// Timer ownership and the socket wait/poll state share one allocation,
/// keeping the interrupt-path TcpEntry itself within its stack-size budget.
pub(crate) struct TcpAsyncState {
    pub(super) timers: TcpTimers,
    sleep: crate::sock_wait::SockWaitQueue,
    subscribers: Spinlock<Option<alloc::sync::Weak<vfs::PollSubscribers>>, StackLockClass>,
    /// The owning open file description (Linux `sk->sk_socket->file`), which
    /// urgent arrival signals through its `f_owner`. Weak, and published by
    /// the same bind that publishes `subscribers`, so the two notification
    /// targets of one socket cannot name different descriptions.
    owner_file: Spinlock<alloc::sync::Weak<vfs::File>, StackLockClass>,
}

impl TcpAsyncState {
    /// # C: O(1)
    pub(crate) const fn new() -> Self {
        Self { timers: TcpTimers::new(), sleep: crate::sock_wait::SockWaitQueue::new(),
               subscribers: Spinlock::new(None),
               owner_file: Spinlock::new(alloc::sync::Weak::new()) }
    }

    /// Socket sleep queue shared by connect, receive, and transmit. # C: O(1)
    pub(crate) fn sleep(&self) -> &crate::sock_wait::SockWaitQueue { &self.sleep }

    /// The owning description, while a descriptor is bound. # C: O(1)
    pub(crate) fn owner_file(&self) -> Option<alloc::sync::Arc<vfs::File>> {
        self.owner_file.lock().upgrade()
    }

    /// Publish the owning description. # C: O(1)
    pub(crate) fn set_owner_file(&self, file: &alloc::sync::Arc<vfs::File>) {
        *self.owner_file.lock() = alloc::sync::Arc::downgrade(file);
    }
}

impl ::core::ops::Deref for TcpAsyncState {
    type Target = Spinlock<Option<alloc::sync::Weak<vfs::PollSubscribers>>, StackLockClass>;
    fn deref(&self) -> &Self::Target { &self.subscribers }
}
