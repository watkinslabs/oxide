//! Socket-owned multipart dump continuation.

extern crate alloc;

use alloc::vec::Vec;

use crate::{nlmsg_align, Nlmsghdr};

/// Largest reply datagram emitted by one continuation turn.  It mirrors the
/// bounded skb allocation used for multipart NETLINK replies while preserving
/// complete nlmsg frames.
pub(crate) const DUMP_CHUNK_BYTES: usize = 4096;

/// The callback-equivalent state for the one multipart dump a NETLINK socket
/// may run at once.  It is deliberately socket-owned: there is no registry
/// beside the socket which could disagree with `/proc/net/netlink`.
pub(crate) struct DumpState {
    reply: Vec<u8>,
    next: usize,
    active: bool,
}

impl DumpState {
    pub(crate) const fn new() -> Self {
        Self { reply: Vec::new(), next: 0, active: false }
    }

    /// Whether this socket has a multipart dump awaiting another turn.
    /// # C: O(1)
    pub(crate) fn active(&self) -> bool { self.active }

    /// Begin one multipart reply and produce its first bounded datagram.
    /// # C: O(reply chunk)
    pub(crate) fn start(&mut self, reply: Vec<u8>) -> Result<Vec<u8>, ()> {
        if self.active { return Err(()); }
        self.reply = reply;
        self.next = 0;
        self.active = true;
        Ok(self.next_chunk().expect("multipart reply has NLMSG_DONE"))
    }

    /// Produce the next reply datagram after userspace consumes the current
    /// one.  The final chunk clears `active` as it is generated, before the
    /// caller reads its `NLMSG_DONE`.
    /// # C: O(reply chunk)
    pub(crate) fn next_chunk(&mut self) -> Option<Vec<u8>> {
        if !self.active { return None; }
        let start = self.next;
        let mut end = start;
        while end + Nlmsghdr::SIZE <= self.reply.len() {
            let Some(hdr) = Nlmsghdr::parse(&self.reply[end..]) else { break; };
            let len = hdr.nlmsg_len as usize;
            if len < Nlmsghdr::SIZE || end.checked_add(len).is_none_or(|last| last > self.reply.len()) {
                break;
            }
            let frame_end = end + nlmsg_align(len);
            if frame_end > self.reply.len() { break; }
            if end != start && frame_end - start > DUMP_CHUNK_BYTES { break; }
            end = frame_end;
            if end - start >= DUMP_CHUNK_BYTES { break; }
        }
        if end == start {
            self.active = false;
            self.reply.clear();
            return None;
        }
        self.next = end;
        let chunk = self.reply[start..end].to_vec();
        if self.next == self.reply.len() {
            self.active = false;
            self.reply.clear();
            self.next = 0;
        }
        Some(chunk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{flags, msg};

    fn frame(typ: u16, bytes: usize) -> Vec<u8> {
        let len = Nlmsghdr::SIZE + bytes;
        let mut out = alloc::vec![0; nlmsg_align(len)];
        Nlmsghdr { nlmsg_len: len as u32, nlmsg_type: typ, nlmsg_flags: flags::NLM_F_MULTI,
            nlmsg_seq: 7, nlmsg_pid: 9 }.write_to(&mut out);
        out
    }

    #[test]
    fn emits_complete_bounded_frames_and_clears_after_final_generation() {
        let mut reply = frame(20, DUMP_CHUNK_BYTES - Nlmsghdr::SIZE);
        reply.extend(frame(msg::NLMSG_DONE, 0));
        let mut dump = DumpState::new();
        let first = dump.start(reply).unwrap();
        assert_eq!(first.len(), DUMP_CHUNK_BYTES);
        assert!(dump.active());
        let last = dump.next_chunk().unwrap();
        assert_eq!(Nlmsghdr::parse(&last).unwrap().nlmsg_type, msg::NLMSG_DONE);
        assert!(!dump.active());
    }
}
