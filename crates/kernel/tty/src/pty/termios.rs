/// Linux c_lflag bits we honour.
pub mod lflag {
    pub const ISIG:    u32 = 0o000001;
    pub const ICANON:  u32 = 0o000002;
    pub const ECHO:    u32 = 0o000010;
    pub const ECHOE:   u32 = 0o000020; // VERASE echoes "\b \b"
    pub const ECHOK:   u32 = 0o000040; // VKILL echoes "\r\n"
    pub const ECHONL:  u32 = 0o000100; // echo NL even when ECHO off
    pub const NOFLSH:  u32 = 0o000200; // don't flush queues on ISIG
    pub const TOSTOP:  u32 = 0o000400; // SIGTTOU on bg-pgrp write
    pub const ECHOCTL: u32 = 0o001000; // echo control chars as ^X
    pub const IEXTEN:  u32 = 0o100000; // enable VWERASE/VLNEXT/VEOL2 (impl-defined input)
}

/// Linux c_iflag bits — input processing on master_write.
pub mod iflag {
    pub const IGNCR:  u32 = 0o000200; // drop \r from input
    pub const ICRNL:  u32 = 0o000400; // translate \r to \n on input
    pub const INLCR:  u32 = 0o000100; // translate \n to \r on input
    pub const IXON:   u32 = 0o002000; // ^S/^Q flow control on output
    pub const IXANY:  u32 = 0o004000; // any input char restarts stopped output
}

/// Linux c_oflag bits — output processing on slave_write.
pub mod oflag {
    pub const OPOST:  u32 = 0o000001; // master switch for output processing
    pub const ONLCR:  u32 = 0o000004; // translate \n to \r\n on output
    pub const OCRNL:  u32 = 0o000010; // translate \r to \n on output
    pub const ONOCR:  u32 = 0o000020; // no \r at column 0 (ignored — no col tracking)
    pub const ONLRET: u32 = 0o000040; // \n moves to col 0 (ignored)
}

/// Default c_lflag at pair creation: matches Linux `stty sane`
/// — ICANON | ECHO | ISIG | ECHOE | ECHOK | ECHOCTL.
pub const DEFAULT_LFLAG: u32 = lflag::ICANON | lflag::ECHO | lflag::ISIG
    | lflag::ECHOE | lflag::ECHOK | lflag::ECHOCTL | lflag::IEXTEN;
/// Default c_iflag at pair creation: ICRNL (Enter sends \r → \n).
pub const DEFAULT_IFLAG: u32 = iflag::ICRNL;
/// Default c_oflag at pair creation: OPOST | ONLCR (\n → \r\n on output).
pub const DEFAULT_OFLAG: u32 = oflag::OPOST | oflag::ONLCR;

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

/// c_cc indices per Linux termios.h. v1 honours VINTR + VEOF +
/// VERASE + VKILL via ldisc dispatch; the rest are stored in the
/// termios image but ignored.
pub mod cc {
    pub const VINTR:    usize = 0;
    pub const VQUIT:    usize = 1;
    pub const VERASE:   usize = 2;
    pub const VKILL:    usize = 3;
    pub const VEOF:     usize = 4;
    pub const VTIME:    usize = 5;
    pub const VMIN:     usize = 6;
    pub const VSWTC:    usize = 7;
    pub const VSTART:   usize = 8;
    pub const VSTOP:    usize = 9;
    pub const VSUSP:    usize = 10;
    pub const VEOL:     usize = 11;
    pub const VREPRINT: usize = 12;
    pub const VDISCARD: usize = 13;
    pub const VWERASE:  usize = 14;
    pub const VLNEXT:   usize = 15;
    pub const VEOL2:    usize = 16;
}

/// Default c_cc[VINTR] = 0x03 (^C).
pub const DEFAULT_VINTR:  u8 = 0x03;
/// Default c_cc[VEOF]   = 0x04 (^D).
pub const DEFAULT_VEOF:   u8 = 0x04;
/// Default c_cc[VERASE] = 0x7F (DEL).
pub const DEFAULT_VERASE: u8 = 0x7F;
/// Default c_cc[VKILL]  = 0x15 (^U).
pub const DEFAULT_VKILL:  u8 = 0x15;
/// Default c_cc[VQUIT]  = 0x1C (^\).
pub const DEFAULT_VQUIT:  u8 = 0x1C;
/// Default c_cc[VSUSP]  = 0x1A (^Z).
pub const DEFAULT_VSUSP:  u8 = 0x1A;
/// Default c_cc[VSTART] = 0x11 (^Q).
pub const DEFAULT_VSTART: u8 = 0x11;
/// Default c_cc[VSTOP]  = 0x13 (^S).
pub const DEFAULT_VSTOP:  u8 = 0x13;
/// Default c_cc[VWERASE] = 0x17 (^W).
pub const DEFAULT_VWERASE: u8 = 0x17;

/// Build a default termios byte image. Matches Linux pty defaults:
/// c_lflag = ICANON|ECHO|ISIG, c_iflag = ICRNL, c_oflag = OPOST|ONLCR,
/// c_cc[VINTR] = 0x03, others 0.
/// # C: O(1)
pub const fn default_termios() -> [u8; TERMIOS_BYTES] {
    let mut t = [0u8; TERMIOS_BYTES];
    let il = DEFAULT_IFLAG.to_le_bytes();
    t[TERMIOS_OFF_IFLAG    ] = il[0];
    t[TERMIOS_OFF_IFLAG + 1] = il[1];
    t[TERMIOS_OFF_IFLAG + 2] = il[2];
    t[TERMIOS_OFF_IFLAG + 3] = il[3];
    let ol = DEFAULT_OFLAG.to_le_bytes();
    t[TERMIOS_OFF_OFLAG    ] = ol[0];
    t[TERMIOS_OFF_OFLAG + 1] = ol[1];
    t[TERMIOS_OFF_OFLAG + 2] = ol[2];
    t[TERMIOS_OFF_OFLAG + 3] = ol[3];
    let lf = DEFAULT_LFLAG.to_le_bytes();
    t[TERMIOS_OFF_LFLAG    ] = lf[0];
    t[TERMIOS_OFF_LFLAG + 1] = lf[1];
    t[TERMIOS_OFF_LFLAG + 2] = lf[2];
    t[TERMIOS_OFF_LFLAG + 3] = lf[3];
    t[TERMIOS_OFF_CC + cc::VINTR ] = DEFAULT_VINTR;
    t[TERMIOS_OFF_CC + cc::VQUIT ] = DEFAULT_VQUIT;
    t[TERMIOS_OFF_CC + cc::VERASE] = DEFAULT_VERASE;
    t[TERMIOS_OFF_CC + cc::VKILL ] = DEFAULT_VKILL;
    t[TERMIOS_OFF_CC + cc::VEOF  ] = DEFAULT_VEOF;
    t[TERMIOS_OFF_CC + cc::VSUSP ] = DEFAULT_VSUSP;
    t[TERMIOS_OFF_CC + cc::VSTART] = DEFAULT_VSTART;
    t[TERMIOS_OFF_CC + cc::VSTOP ] = DEFAULT_VSTOP;
    t[TERMIOS_OFF_CC + cc::VWERASE] = DEFAULT_VWERASE;
    t
}

/// Read a u32 field out of a termios byte image at `off`.
/// # C: O(1)
pub fn read_termios_u32(t: &[u8; TERMIOS_BYTES], off: usize) -> u32 {
    u32::from_le_bytes([t[off], t[off + 1], t[off + 2], t[off + 3]])
}

/// Read the c_lflag field out of a termios byte image.
/// # C: O(1)
pub fn read_lflag(t: &[u8; TERMIOS_BYTES]) -> u32 {
    read_termios_u32(t, TERMIOS_OFF_LFLAG)
}

/// Read the c_iflag field.
/// # C: O(1)
pub fn read_iflag(t: &[u8; TERMIOS_BYTES]) -> u32 {
    read_termios_u32(t, TERMIOS_OFF_IFLAG)
}

/// Read the c_oflag field.
/// # C: O(1)
pub fn read_oflag(t: &[u8; TERMIOS_BYTES]) -> u32 {
    read_termios_u32(t, TERMIOS_OFF_OFLAG)
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
