// `Pkt` packet buffer per `25§5`. v1 hosted-testable shape: a single
// owned byte buffer plus head/data/tail/end offsets so each layer can
// `push` headers in front of payload (for tx) or `pop` headers off
// the front (for rx) without reallocating.
//
// Out of scope: per-CPU `pkt_slab` (`25§5` "Allocated from per-CPU
// slab `pkt_slab`"); the refcount + IRQ-context tx-completion
// callback (`24§3`); `cb` per-layer scratch becomes typed once the
// TCP/UDP layers land.

extern crate alloc;
use alloc::vec::Vec;

use crate::addr::NetIfaceId;

/// Packet buffer error type. Numeric reps Linux-aligned.
#[repr(i32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PktError {
    Einval = 22,
    Enobufs = 105,
}

pub type KResult<T> = core::result::Result<T, PktError>;

/// Default headroom for `push` operations — leaves room for L2 + L3
/// + L4 headers without re-shuffling. 64 bytes covers Ethernet (14)
/// + IPv6 (40) + TCP (20) with slack; `Pkt::new_with_headroom` lets
/// callers pick a different value.
pub const DEFAULT_HEADROOM: usize = 64;

/// `25§5` packet buffer — owns its byte storage. `data` is the
/// offset of the current "front" header (`L2 / L3 / L4` walk via
/// `pop`), `tail` is one past the last payload byte. `data..tail` is
/// the live region; `0..data` is the headroom; `tail..end` is the
/// tailroom.
pub struct Pkt {
    buf:  Vec<u8>,
    data: u32,
    tail: u32,
    pub iface:    Option<NetIfaceId>,
    pub proto:    u16,
    pub timestamp_ns: u64,
}

impl Pkt {
    /// New packet with `payload_len` bytes of zero payload + a
    /// `DEFAULT_HEADROOM` headroom in front of it. Total capacity =
    /// `DEFAULT_HEADROOM + payload_len`.
    /// # C: O(payload_len)
    pub fn new(payload_len: usize) -> Self {
        Self::new_with_headroom(DEFAULT_HEADROOM, payload_len)
    }

    /// # C: O(headroom + payload_len)
    pub fn new_with_headroom(headroom: usize, payload_len: usize) -> Self {
        let total = headroom + payload_len;
        let buf = alloc::vec![0u8; total];
        Self {
            buf,
            data: headroom as u32,
            tail: (headroom + payload_len) as u32,
            iface: None, proto: 0, timestamp_ns: 0,
        }
    }

    /// Construct an empty buffer with `headroom` bytes reserved up
    /// front and `capacity` total bytes available. `data == tail ==
    /// headroom`; the caller fills with `put`. Use this when the
    /// payload size is determined incrementally (tx-side header
    /// prepend then payload append).
    /// # C: O(capacity)
    pub fn with_capacity(headroom: usize, capacity: usize) -> Self {
        debug_assert!(headroom <= capacity);
        let buf = alloc::vec![0u8; capacity];
        Self {
            buf,
            data: headroom as u32,
            tail: headroom as u32,
            iface: None, proto: 0, timestamp_ns: 0,
        }
    }

    /// Wrap an existing `Vec<u8>` with `data == 0` and `tail == len`.
    /// Used by `deliver_rx` paths where the driver hands over a fully
    /// populated frame.
    /// # C: O(1)
    pub fn from_owned(buf: Vec<u8>) -> Self {
        let len = buf.len() as u32;
        Self { buf, data: 0, tail: len, iface: None, proto: 0, timestamp_ns: 0 }
    }

    /// # C: O(1)
    pub fn len(&self) -> usize { (self.tail - self.data) as usize }

    /// # C: O(1)
    pub fn is_empty(&self) -> bool { self.tail == self.data }

    /// # C: O(1)
    pub fn capacity(&self) -> usize { self.buf.len() }

    /// # C: O(1)
    pub fn headroom(&self) -> usize { self.data as usize }

    /// # C: O(1)
    pub fn tailroom(&self) -> usize { self.buf.len() - self.tail as usize }

    /// # C: O(1)
    pub fn data(&self) -> &[u8] {
        &self.buf[self.data as usize..self.tail as usize]
    }

    /// # C: O(1)
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.data as usize..self.tail as usize]
    }

    /// Reserve `n` bytes at the front. Fails with `Enobufs` when the
    /// headroom is exhausted.
    /// # C: O(1)
    pub fn push(&mut self, n: usize) -> KResult<&mut [u8]> {
        if (n as u32) > self.data { return Err(PktError::Enobufs); }
        self.data -= n as u32;
        Ok(&mut self.buf[self.data as usize..self.data as usize + n])
    }

    /// Drop `n` bytes from the front (rx walks L2 -> L3 -> L4 by
    /// popping each header in turn).
    /// # C: O(1)
    pub fn pop(&mut self, n: usize) -> KResult<()> {
        let new_data = self.data.checked_add(n as u32).ok_or(PktError::Einval)?;
        if new_data > self.tail { return Err(PktError::Einval); }
        self.data = new_data;
        Ok(())
    }

    /// Append `n` bytes at the tail. Fails with `Enobufs` when the
    /// tailroom is exhausted.
    /// # C: O(1)
    pub fn put(&mut self, n: usize) -> KResult<&mut [u8]> {
        let new_tail = self.tail.checked_add(n as u32).ok_or(PktError::Einval)?;
        if new_tail as usize > self.buf.len() { return Err(PktError::Enobufs); }
        let start = self.tail as usize;
        self.tail = new_tail;
        Ok(&mut self.buf[start..start + n])
    }

    /// Drop `n` bytes from the tail (e.g. trim a CRC).
    /// # C: O(1)
    pub fn trim(&mut self, n: usize) -> KResult<()> {
        let n = n as u32;
        if self.tail.checked_sub(n).map_or(true, |t| t < self.data) {
            return Err(PktError::Einval);
        }
        self.tail -= n;
        Ok(())
    }

    /// Reset to a clean buffer with `headroom` bytes of front space
    /// and zero payload — re-use of an `Arc<Pkt>` after the previous
    /// caller is done.
    /// # C: O(1)
    pub fn reset(&mut self, headroom: usize) {
        let cap = self.buf.len() as u32;
        let h = (headroom as u32).min(cap);
        self.data = h;
        self.tail = h;
    }
}
