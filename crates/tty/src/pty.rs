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

/// Linux x86_64 `struct termios` size. Userspace tcgetattr / tcsetattr
/// pass exactly this many bytes through TCGETS / TCSETS.
pub const TERMIOS_BYTES: usize = 60;

/// Layout of the Linux `struct termios`:
///   off 0..4   c_iflag (u32)
///   off 4..8   c_oflag (u32)
///   off 8..12  c_cflag (u32)
///   off 12..16 c_lflag (u32)
///   off 16     c_line  (u8)
///   off 17..36 c_cc[19] (u8 each)
///   off 36..40 c_ispeed (u32)
///   off 40..44 c_ospeed (u32)
///   off 44..60 padding
pub const TERMIOS_OFF_IFLAG:  usize = 0;
pub const TERMIOS_OFF_OFLAG:  usize = 4;
pub const TERMIOS_OFF_CFLAG:  usize = 8;
pub const TERMIOS_OFF_LFLAG:  usize = 12;
pub const TERMIOS_OFF_LINE:   usize = 16;
pub const TERMIOS_OFF_CC:     usize = 17;
pub const TERMIOS_OFF_ISPEED: usize = 36;
pub const TERMIOS_OFF_OSPEED: usize = 40;

/// Number of c_cc control characters in Linux termios.
pub const NCCS: usize = 19;

/// c_cc indexes we honour. Linux's termios.h has many more; v1
/// reads VINTR for ldisc dispatch.
pub mod cc {
    pub const VINTR: usize = 0;
}

/// Default c_cc[VINTR] = 0x03 (^C).
pub const DEFAULT_VINTR: u8 = 0x03;

/// Build a default termios byte image. Matches Linux pty defaults:
/// c_lflag = ICANON|ECHO|ISIG, c_cc[VINTR] = 0x03, others 0.
/// # C: O(1)
pub const fn default_termios() -> [u8; TERMIOS_BYTES] {
    let mut t = [0u8; TERMIOS_BYTES];
    let lf = DEFAULT_LFLAG.to_le_bytes();
    t[TERMIOS_OFF_LFLAG    ] = lf[0];
    t[TERMIOS_OFF_LFLAG + 1] = lf[1];
    t[TERMIOS_OFF_LFLAG + 2] = lf[2];
    t[TERMIOS_OFF_LFLAG + 3] = lf[3];
    t[TERMIOS_OFF_CC + cc::VINTR] = DEFAULT_VINTR;
    t
}

/// Read the c_lflag field out of a termios byte image.
/// # C: O(1)
pub fn read_lflag(t: &[u8; TERMIOS_BYTES]) -> u32 {
    u32::from_le_bytes([
        t[TERMIOS_OFF_LFLAG    ], t[TERMIOS_OFF_LFLAG + 1],
        t[TERMIOS_OFF_LFLAG + 2], t[TERMIOS_OFF_LFLAG + 3],
    ])
}

/// Read c_cc[VINTR] out of a termios byte image.
/// # C: O(1)
pub fn read_vintr(t: &[u8; TERMIOS_BYTES]) -> u8 { t[TERMIOS_OFF_CC + cc::VINTR] }

/// Linux `struct winsize` per ioctl_tty(2): rows, cols, xpixel, ypixel
/// (each u16). TIOCGWINSZ reads, TIOCSWINSZ writes; SIGWINCH is sent
/// to the foreground pgrp on change (28§5).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Winsize {
    pub rows:   u16,
    pub cols:   u16,
    pub xpixel: u16,
    pub ypixel: u16,
}

impl Winsize {
    /// Default 24×80, matching Linux pty defaults + most terminal emulators.
    /// # C: O(1)
    pub const fn default_pty() -> Self {
        Self { rows: 24, cols: 80, xpixel: 0, ypixel: 0 }
    }

    /// Encode into the 8-byte little-endian buffer userspace expects.
    /// # C: O(1)
    pub fn to_le_bytes(&self) -> [u8; 8] {
        let mut b = [0u8; 8];
        b[0..2].copy_from_slice(&self.rows.to_le_bytes());
        b[2..4].copy_from_slice(&self.cols.to_le_bytes());
        b[4..6].copy_from_slice(&self.xpixel.to_le_bytes());
        b[6..8].copy_from_slice(&self.ypixel.to_le_bytes());
        b
    }

    /// Decode from the 8-byte little-endian wire form (TIOCSWINSZ arg).
    /// # C: O(1)
    pub fn from_le_bytes(b: &[u8; 8]) -> Self {
        Self {
            rows:   u16::from_le_bytes([b[0], b[1]]),
            cols:   u16::from_le_bytes([b[2], b[3]]),
            xpixel: u16::from_le_bytes([b[4], b[5]]),
            ypixel: u16::from_le_bytes([b[6], b[7]]),
        }
    }
}

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
    /// Foreground process group id per `28§4` / TIOCSPGRP.
    pub foreground_pgid: u32,
    /// Linux `struct termios` byte image (60 B). TCGETS copies out;
    /// TCSETS copies in wholesale. Hot-path readers (`master_write`,
    /// `slave_read`) consult `read_lflag` / `read_vintr`.
    pub termios: [u8; TERMIOS_BYTES],
    /// Window size per `ioctl_tty(2)`. TIOCGWINSZ reads; TIOCSWINSZ
    /// writes + sets `pending_sigwinch` so the kernel-side adapter
    /// posts SIGWINCH to the foreground pgrp.
    pub winsize: Winsize,
    /// Set when a ^C (or whatever c_cc[VINTR] points at) hits
    /// master_write while `lflag & ISIG`. Kernel-side adapter
    /// inspects + clears this to deliver SIGINT to `foreground_pgid`.
    pub pending_sigint: bool,
    /// Set on TIOCSWINSZ when the new size differs. Cleared by the
    /// kernel-side ioctl handler after posting SIGWINCH.
    pub pending_sigwinch: bool,
}

impl Pair {
    /// Convenience accessor for the c_lflag field.
    /// # C: O(1)
    pub fn lflag(&self) -> u32 { read_lflag(&self.termios) }

    /// Convenience accessor for c_cc[VINTR].
    /// # C: O(1)
    pub fn vintr(&self) -> u8 { read_vintr(&self.termios) }

    /// Construct a raw-mode pair (termios all-zero). Existing callers
    /// expect direct-passthrough semantics. Cooked-mode ptys overwrite
    /// `termios = default_termios()` after construction.
    /// # C: O(1)
    pub fn new(pts_num: u32) -> Self {
        Self {
            pts_num,
            m_to_s: Ring::new(), s_to_m: Ring::new(),
            hung_up: false, foreground_pgid: 0,
            termios: [0u8; TERMIOS_BYTES],
            winsize: Winsize::default_pty(),
            pending_sigint: false,
            pending_sigwinch: false,
        }
    }

    /// Update `winsize`. Sets `pending_sigwinch` if the new size
    /// differs from the old (kernel-side will dispatch SIGWINCH).
    /// # C: O(1)
    pub fn set_winsize(&mut self, ws: Winsize) {
        if ws != self.winsize {
            self.winsize = ws;
            self.pending_sigwinch = true;
        }
    }

    /// Master writes input (keystrokes). With ECHO, every accepted
    /// byte is also enqueued to s_to_m (echoed back to master read).
    /// With ISIG, a c_cc[VINTR] byte is dropped from the input stream
    /// and `pending_sigint` is set instead — kernel-side dispatches.
    /// Returns total bytes consumed from `src`.
    /// # C: O(N)
    pub fn master_write(&mut self, src: &[u8]) -> usize {
        let lflag = self.lflag();
        let vintr = self.vintr();
        let isig  = (lflag & lflag::ISIG) != 0 && vintr != 0;
        let echo  = (lflag & lflag::ECHO) != 0;
        let mut consumed = 0;
        for &b in src {
            if isig && b == vintr {
                self.pending_sigint = true;
                consumed += 1;
                if echo {
                    let _ = self.s_to_m.write(b"^C");
                }
                continue;
            }
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
        if (self.lflag() & lflag::ICANON) == 0 {
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
