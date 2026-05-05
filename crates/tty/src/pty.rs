// PTY pair core per `28§5`. Master/slave back-to-back ring buffers
// + termios-driven line discipline. The kernel-side adapter wraps
// each pair in a Spinlock; this layer is lock-free so semantics
// live in hosted tests.
//
// Linux PTY semantics (master ⇄ slave):
//   * write to master → bytes appear on slave reads (keystrokes)
//   * write to slave  → bytes appear on master reads (program output)
//
// Cooked mode (default — ICANON | ECHO | ISIG):
//   * Master writes are echoed back to master read (ECHO).
//   * Slave reads are line-buffered (ICANON): nothing until \n
//     appears in the input buffer; the read drains up to and
//     including that \n.
//   * VINTR (^C, 0x03) records the desire to deliver SIGINT to the
//     foreground_pgid; kernel-side adapter dispatches.

extern crate alloc;
use alloc::collections::VecDeque;

/// Linux c_lflag bits we honour. Many more exist; kernel ignores
/// the rest (Linux returns success on TCSETS regardless).
pub mod lflag {
    pub const ISIG:   u32 = 0o000001;
    pub const ICANON: u32 = 0o000002;
    pub const ECHO:   u32 = 0o000010;
}

/// Default c_lflag at pair creation: ICANON | ECHO | ISIG. Matches
/// Linux's pty default and what shells expect to inherit.
pub const DEFAULT_LFLAG: u32 = lflag::ICANON | lflag::ECHO | lflag::ISIG;

/// VINTR character (^C). Hardcoded — Linux lets c_cc[VINTR] override,
/// not yet wired.
pub const VINTR: u8 = 0x03;

/// Maximum bytes buffered per direction. Matches Linux's default
/// 4 KiB per pty queue. Writes that would overflow return `Eagain`
/// when non-blocking; v1 is non-blocking always (drops excess).
pub const PTY_BUF_BYTES: usize = 4096;

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
    /// Termios c_lflag bits. Default `DEFAULT_LFLAG` (cooked mode).
    /// Updated by TCSETS; read by TCGETS.
    pub lflag: u32,
    /// Set when a ^C (VINTR) appears in master_write while
    /// `lflag & ISIG`. Kernel-side adapter inspects + clears this
    /// to deliver SIGINT to `foreground_pgid`. v1 records intent only.
    pub pending_sigint: bool,
}

impl Pair {
    /// Construct a raw-mode pair (`lflag == 0`). Existing callers
    /// expect direct-passthrough semantics. Cooked-mode ptys flip
    /// `lflag = DEFAULT_LFLAG` after construction (kernel adapter).
    /// # C: O(1)
    pub fn new(pts_num: u32) -> Self {
        Self {
            pts_num,
            m_to_s: Ring::new(), s_to_m: Ring::new(),
            hung_up: false, foreground_pgid: 0,
            lflag: 0,
            pending_sigint: false,
        }
    }

    /// Master writes input (keystrokes). With ECHO, every accepted
    /// byte is also enqueued to s_to_m (echoed back to master read).
    /// With ISIG, a VINTR byte is dropped from the input stream and
    /// `pending_sigint` is set instead — kernel-side dispatches.
    /// Returns total bytes consumed from `src` (including any byte
    /// that triggered SIGINT — the byte is *removed* from the input
    /// stream, matching Linux ldisc behaviour).
    /// # C: O(N)
    pub fn master_write(&mut self, src: &[u8]) -> usize {
        let isig   = (self.lflag & lflag::ISIG)   != 0;
        let echo   = (self.lflag & lflag::ECHO)   != 0;
        let mut consumed = 0;
        for &b in src {
            if isig && b == VINTR {
                self.pending_sigint = true;
                consumed += 1;
                if echo {
                    // Visual ^C — Linux echoes "^C" to the terminal.
                    let _ = self.s_to_m.write(b"^C");
                }
                continue;
            }
            // No room → stop here; caller retries / EAGAIN.
            if self.m_to_s.space() == 0 { break; }
            self.m_to_s.write(&[b]);
            if echo { let _ = self.s_to_m.write(&[b]); }
            consumed += 1;
        }
        consumed
    }

    /// Slave reads input. Under ICANON, returns 0 until a `\n` is
    /// present; then drains *up to and including* that newline (or
    /// up to dst.len()). Raw mode drains whatever is available.
    /// # C: O(N)
    pub fn slave_read(&mut self, dst: &mut [u8]) -> usize {
        if (self.lflag & lflag::ICANON) == 0 {
            return self.m_to_s.read(dst);
        }
        // ICANON: drain only if a complete line is buffered.
        let line_end = self.m_to_s.buf.iter().position(|&b| b == b'\n');
        match line_end {
            None    => 0,
            Some(i) => {
                let limit = (i + 1).min(dst.len());
                let mut tmp = [0u8; 1];
                let mut n = 0;
                while n < limit {
                    self.m_to_s.read(&mut tmp);
                    dst[n] = tmp[0];
                    n += 1;
                }
                n
            }
        }
    }

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
