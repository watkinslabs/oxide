use alloc::collections::VecDeque;

use super::super::termios::PTY_BUF_BYTES;

/// One direction of a PTY pair (master→slave or slave→master).
/// Backed by `VecDeque<u8>`; not thread-safe — wrap in a Spinlock.
pub struct Ring {
    pub(crate) buf: VecDeque<u8>,
}

impl Ring {
    /// # C: O(1)
    pub const fn capacity() -> usize { PTY_BUF_BYTES }

    /// # C: O(1)
    pub fn new() -> Self { Self { buf: VecDeque::new() } }

    /// Bytes currently queued.
    /// # C: O(1)
    pub fn len(&self) -> usize { self.buf.len() }

    /// True when no bytes are queued.
    /// # C: O(1)
    pub fn is_empty(&self) -> bool { self.buf.is_empty() }

    /// Bytes that can still be enqueued before hitting `PTY_BUF_BYTES`.
    /// # C: O(1)
    pub fn space(&self) -> usize {
        PTY_BUF_BYTES.saturating_sub(self.buf.len())
    }

    /// Append up to `space()` bytes; returns the count actually
    /// enqueued. Excess is dropped — caller decides whether to
    /// retry, EAGAIN, or block.
    /// # C: O(N_written)
    pub fn write(&mut self, src: &[u8]) -> usize {
        let n = src.len().min(self.space());
        for &b in &src[..n] { self.buf.push_back(b); }
        n
    }

    /// Discard all queued bytes (TCFLSH). # C: O(N) drop
    pub fn clear(&mut self) { self.buf.clear(); }

    /// Drain up to `dst.len()` bytes into `dst`; returns the count
    /// actually copied. Zero return means the queue was empty.
    /// # C: O(N_read)
    pub fn read(&mut self, dst: &mut [u8]) -> usize {
        let n = dst.len().min(self.buf.len());
        for slot in &mut dst[..n] {
            *slot = self.buf.pop_front().expect("len() validated above");
        }
        n
    }
}

impl Default for Ring {
    fn default() -> Self { Self::new() }
}
