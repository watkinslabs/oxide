//! Virtio-vsock `SOCK_SEQPACKET` receive record assembly.
//!
//! Virtio may deliver one logical record in several `OP_RW` frames.  The
//! `VIRTIO_VSOCK_SEQ_EOM` flag makes the assembled message observable; until
//! then it must not satisfy a reader.  `VIRTIO_VSOCK_SEQ_EOR` belongs to that
//! completed message and is propagated unchanged to the message owner.

use alloc::{collections::VecDeque, vec::Vec};

use super::{VIRTIO_VSOCK_SEQ_EOM, VIRTIO_VSOCK_SEQ_EOR};

const NO_RW_FLAGS: u32 = 0;
const NO_READY_BYTES: usize = 0;

/// One completed record, retained until a non-peek receive consumes it.
/// # C: O(1)
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SeqpacketRecord {
    bytes: Vec<u8>,
    end_of_record: bool,
}

/// Result metadata for one completed-record receive transaction.
/// # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SeqpacketDelivery {
    /// Bytes copied into the caller's supplied capacity.
    pub copied_len: usize,
    /// Complete logical message length, before capacity truncation.
    pub message_len: usize,
    /// True when the caller's capacity could not hold the whole message.
    pub truncated: bool,
    /// Peer-provided `MSG_EOR` state for this message.
    pub end_of_record: bool,
}

impl SeqpacketRecord {
    /// Payload bytes in this completed message. # C: O(1)
    pub fn bytes(&self) -> &[u8] { &self.bytes }

    /// Whether the peer set `MSG_EOR` on this message. # C: O(1)
    pub const fn end_of_record(&self) -> bool { self.end_of_record }
}

/// Completed-record queue plus the single incomplete virtio message.
/// # C: O(1)
#[derive(Default)]
pub struct SeqpacketRx {
    assembling: Vec<u8>,
    complete: VecDeque<SeqpacketRecord>,
    discarding: bool,
}

impl SeqpacketRx {
    /// Append one virtio `OP_RW` fragment. A record becomes visible only when
    /// the fragment carries `SEQ_EOM`. # C: O(fragment length)
    pub fn push_fragment(&mut self, payload: &[u8], flags: u32) {
        if self.discarding {
            if flags & VIRTIO_VSOCK_SEQ_EOM != NO_RW_FLAGS { self.discarding = false; }
            return;
        }
        self.assembling.extend_from_slice(payload);
        if flags & VIRTIO_VSOCK_SEQ_EOM == NO_RW_FLAGS { return; }
        let bytes = core::mem::take(&mut self.assembling);
        self.complete.push_back(SeqpacketRecord {
            bytes,
            end_of_record: flags & VIRTIO_VSOCK_SEQ_EOR != 0,
        });
    }

    /// Discard the current message after a receive filter drops one fragment.
    /// Later fragments remain hidden until this message's `SEQ_EOM` arrives.
    /// # C: O(N partial bytes)
    pub fn drop_fragment(&mut self, flags: u32) {
        self.assembling.clear();
        self.discarding = flags & VIRTIO_VSOCK_SEQ_EOM == NO_RW_FLAGS;
    }

    /// Number of fully assembled messages ready for receive. # C: O(1)
    pub fn ready_count(&self) -> usize { self.complete.len() }

    /// Number of bytes in the next full message, or zero when none is ready.
    /// # C: O(1)
    pub fn next_len(&self) -> usize {
        self.complete.front().map(|record| record.bytes.len()).unwrap_or(NO_READY_BYTES)
    }

    /// Borrow the next completed record without consuming it. # C: O(1)
    pub fn peek(&self) -> Option<&SeqpacketRecord> { self.complete.front() }

    /// Consume the next completed record. # C: O(1)
    pub fn pop(&mut self) -> Option<SeqpacketRecord> { self.complete.pop_front() }

    /// Copy one complete message transactionally. A failed callback leaves the
    /// record queued; a successful non-peek callback consumes exactly it.
    /// # C: O(min(capacity, message length))
    pub fn receive_with<R, E>(&mut self, capacity: usize, peek: bool,
        copy: impl FnOnce(&[u8]) -> Result<R, E>) -> Result<Option<(R, SeqpacketDelivery)>, E>
    {
        let Some(record) = self.complete.front() else { return Ok(None); };
        let message_len = record.bytes.len();
        let copied_len = core::cmp::min(capacity, message_len);
        let delivery = SeqpacketDelivery {
            copied_len,
            message_len,
            truncated: copied_len != message_len,
            end_of_record: record.end_of_record,
        };
        let result = copy(&record.bytes[..copied_len])?;
        if !peek { let _ = self.complete.pop_front(); }
        Ok(Some((result, delivery)))
    }

    /// Clear both ready and incomplete receive state during terminal teardown.
    /// # C: O(N queued bytes)
    pub fn clear(&mut self) {
        self.assembling.clear();
        self.complete.clear();
        self.discarding = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIRST_FRAGMENT: &[u8] = b"first-";
    const SECOND_FRAGMENT: &[u8] = b"record";
    const COMPLETE_RECORD: &[u8] = b"first-record";
    const FOLLOWING_RECORD: &[u8] = b"next";
    const NO_FLAGS: u32 = 0;
    const NO_READY_RECORDS: usize = 0;
    const ONE_READY_RECORD: usize = 1;
    const SMALL_CAPACITY: usize = 3;

    #[test]
    fn fragments_remain_hidden_until_end_of_message() {
        let mut queue = SeqpacketRx::default();
        queue.push_fragment(FIRST_FRAGMENT, NO_FLAGS);
        assert_eq!(queue.ready_count(), NO_READY_RECORDS);
        assert_eq!(queue.next_len(), NO_READY_BYTES);
        queue.push_fragment(SECOND_FRAGMENT, VIRTIO_VSOCK_SEQ_EOM | VIRTIO_VSOCK_SEQ_EOR);
        assert_eq!(queue.ready_count(), ONE_READY_RECORD);
        let record = queue.peek().expect("completed record");
        assert_eq!(record.bytes(), COMPLETE_RECORD);
        assert!(record.end_of_record());
    }

    #[test]
    fn consume_preserves_following_record_boundary() {
        let mut queue = SeqpacketRx::default();
        queue.push_fragment(COMPLETE_RECORD, VIRTIO_VSOCK_SEQ_EOM);
        queue.push_fragment(FOLLOWING_RECORD, VIRTIO_VSOCK_SEQ_EOM);
        assert_eq!(queue.pop().expect("first record").bytes(), COMPLETE_RECORD);
        assert_eq!(queue.peek().expect("second record").bytes(), FOLLOWING_RECORD);
    }

    #[test]
    fn dropped_fragment_discards_its_entire_message() {
        const DROPPED_FRAGMENT: &[u8] = b"dropped";
        const DROPPED_TAIL: &[u8] = b"tail";
        let mut queue = SeqpacketRx::default();
        queue.push_fragment(DROPPED_FRAGMENT, NO_FLAGS);
        queue.drop_fragment(NO_FLAGS);
        queue.push_fragment(DROPPED_TAIL, VIRTIO_VSOCK_SEQ_EOM);
        assert_eq!(queue.ready_count(), NO_READY_RECORDS);
        queue.push_fragment(FOLLOWING_RECORD, VIRTIO_VSOCK_SEQ_EOM);
        assert_eq!(queue.pop().expect("following record").bytes(), FOLLOWING_RECORD);
    }

    #[test]
    fn receive_is_transactional_and_reports_record_metadata() {
        let mut queue = SeqpacketRx::default();
        queue.push_fragment(COMPLETE_RECORD, VIRTIO_VSOCK_SEQ_EOM | VIRTIO_VSOCK_SEQ_EOR);
        let failed: Result<Option<((), SeqpacketDelivery)>, ()> = queue.receive_with(
            SMALL_CAPACITY, false, |_| Err(()));
        assert_eq!(failed, Err(()));
        assert_eq!(queue.ready_count(), 1);
        let delivered = queue.receive_with(SMALL_CAPACITY, false,
            |bytes| Ok::<_, ()>(bytes.to_vec())).expect("copy succeeds").expect("record ready");
        assert_eq!(delivered.0, COMPLETE_RECORD[..SMALL_CAPACITY]);
        assert_eq!(delivered.1, SeqpacketDelivery {
            copied_len: SMALL_CAPACITY,
            message_len: COMPLETE_RECORD.len(),
            truncated: true,
            end_of_record: true,
        });
        assert_eq!(queue.ready_count(), NO_READY_RECORDS);
    }
}
