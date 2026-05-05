// PTY pair core per `28§5`. Master/slave back-to-back ring buffers
// without locking — the kernel-side adapter wraps each ring in a
// Spinlock; this lets the queue semantics live in hosted tests.
//
// Linux PTY semantics (master ⇄ slave):
//   * write to master → bytes appear on slave reads (input/keystrokes)
//   * write to slave  → bytes appear on master reads (program output)
//
// v1 is raw mode only. Cooked-mode line discipline (echo, line
// buffering, signal generation on ^C) rides a follow-up; the
// kernel-side ldisc layer will wrap the same `Pair`.

extern crate alloc;
use alloc::collections::VecDeque;

/// Maximum bytes buffered per direction. Matches Linux's default
/// 4 KiB per pty queue. Writes that would overflow return `Eagain`
/// when non-blocking; v1 is non-blocking always (drops excess).
pub const PTY_BUF_BYTES: usize = 4096;

/// One direction of a PTY pair (master→slave or slave→master).
/// Backed by `VecDeque<u8>`; not thread-safe — wrap in a Spinlock.
pub struct Ring {
    buf: VecDeque<u8>,
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

/// A master/slave PTY pair.
///
/// `m_to_s` carries bytes the master *wrote* (keystrokes the slave
/// will *read*); `s_to_m` carries bytes the slave *wrote* (program
/// output the master will *read*).
///
/// Lock placement is the caller's choice — typically one Spinlock
/// per ring rather than one over the whole pair, so master read
/// doesn't serialise with slave read.
pub struct Pair {
    pub pts_num: u32,
    pub m_to_s:  Ring,
    pub s_to_m:  Ring,
    /// True after either side calls `hangup` (slave close on the
    /// final fd). Subsequent reads on the opposite side return EOF.
    pub hung_up: bool,
    /// Foreground process group id per `28§4` / TIOCSPGRP. 0 = no
    /// foreground group set yet (TIOCGPGRP returns 0 in that case).
    /// Shells write this with TIOCSPGRP on fork-then-exec.
    pub foreground_pgid: u32,
}

impl Pair {
    /// # C: O(1)
    pub fn new(pts_num: u32) -> Self {
        Self {
            pts_num,
            m_to_s: Ring::new(), s_to_m: Ring::new(),
            hung_up: false, foreground_pgid: 0,
        }
    }

    /// Master writes input (keystrokes). Returns bytes accepted.
    /// # C: O(N)
    pub fn master_write(&mut self, src: &[u8]) -> usize { self.m_to_s.write(src) }

    /// Slave reads input. Returns 0 + hung_up=true → EOF.
    /// # C: O(N)
    pub fn slave_read(&mut self, dst: &mut [u8]) -> usize { self.m_to_s.read(dst) }

    /// Slave writes output (program text).
    /// # C: O(N)
    pub fn slave_write(&mut self, src: &[u8]) -> usize { self.s_to_m.write(src) }

    /// Master reads program output.
    /// # C: O(N)
    pub fn master_read(&mut self, dst: &mut [u8]) -> usize { self.s_to_m.read(dst) }

    /// Mark the pair hung-up (final fd on one side closed). Reads
    /// on the surviving side that find no buffered data return EOF.
    /// # C: O(1)
    pub fn hangup(&mut self) { self.hung_up = true; }
}

#[cfg(test)]
mod tests;
