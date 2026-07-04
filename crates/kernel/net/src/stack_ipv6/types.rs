use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use sync::{Spinlock, Socket as StackLockClass};

use crate::addr::Ipv6Addr;

pub struct Udp6RxQueue {
    pub bound_ip: Ipv6Addr,
    pub bound_port: u16,
    pub q: Spinlock<VecDeque<(Ipv6Addr, u16, Vec<u8>)>, StackLockClass>,
    #[cfg(target_os = "oxide-kernel")]
    pub waiters: sched::live::WaitList,
    pub error_eno: core::sync::atomic::AtomicI32,
    pub bound_ifindex: core::sync::atomic::AtomicU32,
    pub poll_subs: Spinlock<Option<alloc::sync::Weak<vfs::PollSubscribers>>, StackLockClass>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Ipv6IfaceAddr {
    pub addr: Ipv6Addr,
    pub prefixlen: u8,
    pub preferred: u32,
    pub valid: u32,
}

impl Ipv6IfaceAddr {
    pub const PERMANENT: (u32, u32) = (u32::MAX, u32::MAX);
}

impl Udp6RxQueue {
    pub fn new(bound_ip: Ipv6Addr, bound_port: u16) -> Self {
        Self {
            bound_ip,
            bound_port,
            q: Spinlock::new(VecDeque::new()),
            #[cfg(target_os = "oxide-kernel")]
            waiters: sched::live::WaitList::new(),
            error_eno: core::sync::atomic::AtomicI32::new(0),
            bound_ifindex: core::sync::atomic::AtomicU32::new(0),
            poll_subs: Spinlock::new(None),
        }
    }

    pub fn take_error(&self) -> i32 {
        self.error_eno.swap(0, core::sync::atomic::Ordering::AcqRel)
    }

    pub fn register_poll_subs(&self, subs: &Arc<vfs::PollSubscribers>) {
        *self.poll_subs.lock() = Some(Arc::downgrade(subs));
    }
}
