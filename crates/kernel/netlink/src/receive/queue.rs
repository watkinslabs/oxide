use super::*;

/// One socket-owned NETLINK receive queue. Byte accounting stays beside the
/// datagram container so multicast pressure and dequeue share one invariant.
pub(crate) struct ReceiveQueue {
    pub(super) datagrams: alloc::collections::VecDeque<(
        Vec<u8>, u32, u32, Option<i32>, SenderCreds, Option<Vec<u8>>,
    )>,
    pub(crate) bytes: usize,
}

impl ReceiveQueue {
    pub(crate) const fn new() -> Self {
        Self { datagrams: alloc::collections::VecDeque::new(), bytes: 0 }
    }

    fn charge(bytes: &Vec<u8>) -> usize {
        bytes.capacity().saturating_add(core::mem::size_of::<(
            Vec<u8>, u32, u32, Option<i32>, SenderCreds, Option<Vec<u8>>,
        )>())
    }

    /// Charge one datagram to the queue budget and queue it. # C: O(1)
    pub(crate) fn push(&mut self, bytes: Vec<u8>, src_port: u32, multicast_group: u32,
                       nsid: Option<i32>, creds: SenderCreds, security: Option<Vec<u8>>) {
        self.bytes = self.bytes.saturating_add(Self::charge(&bytes));
        self.datagrams.push_back((bytes, src_port, multicast_group, nsid, creds, security));
    }

    pub(crate) fn pop(&mut self) -> Option<(
        Vec<u8>, u32, u32, Option<i32>, SenderCreds, Option<Vec<u8>>,
    )> {
        let dgram = self.datagrams.pop_front()?;
        self.bytes = self.bytes.saturating_sub(Self::charge(&dgram.0));
        Some(dgram)
    }

    pub(crate) fn is_empty(&self) -> bool { self.datagrams.is_empty() }
}
