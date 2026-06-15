//! termios — terminal attributes (docs/59§6 G17c). The glibc 60-byte `struct
//! termios` (c_cc[32] + c_ispeed/c_ospeed). Pure flag/speed helpers
//! (cfmakeraw/cf{get,set}{i,o}speed) are hosted-tested; tc* are ioctl shims.
//! ABI-checked vs libc::termios.
#![allow(non_camel_case_types)] // C ABI type names (tcflag_t/cc_t/speed_t/termios)

pub type tcflag_t = u32;
pub type cc_t = u8;
pub type speed_t = u32;
pub const NCCS: usize = 32;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct termios {
    pub c_iflag: tcflag_t,
    pub c_oflag: tcflag_t,
    pub c_cflag: tcflag_t,
    pub c_lflag: tcflag_t,
    pub c_line: cc_t,
    pub c_cc: [cc_t; NCCS],
    pub c_ispeed: speed_t,
    pub c_ospeed: speed_t,
}

// c_iflag bits
const IGNBRK: u32 = 0o000001; const BRKINT: u32 = 0o000002; const PARMRK: u32 = 0o000010;
const ISTRIP: u32 = 0o000040; const INLCR: u32 = 0o000100; const IGNCR: u32 = 0o000200;
const ICRNL: u32 = 0o000400; const IXON: u32 = 0o002000;
// c_oflag bits
const OPOST: u32 = 0o000001;
// c_lflag bits
const ISIG: u32 = 0o000001; const ICANON: u32 = 0o000002; const ECHO: u32 = 0o000010;
const ECHONL: u32 = 0o000100; const IEXTEN: u32 = 0o100000;
// c_cflag bits
const CSIZE: u32 = 0o000060; const CS8: u32 = 0o000060; const PARENB: u32 = 0o000400;
const CBAUD: u32 = 0o010017;
// c_cc indices
const VTIME: usize = 5; const VMIN: usize = 6;

/// Set raw mode in place (per the cfmakeraw(3) man page).
/// # C: void cfmakeraw(struct termios *)
pub(crate) fn cfmakeraw_into(t: &mut termios) {
    t.c_iflag &= !(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON);
    t.c_oflag &= !OPOST;
    t.c_lflag &= !(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
    t.c_cflag &= !(CSIZE | PARENB);
    t.c_cflag |= CS8;
    t.c_cc[VMIN] = 1;
    t.c_cc[VTIME] = 0;
}

/// # C: speed_t cfgetospeed(const struct termios *)
pub(crate) fn cfgetospeed_of(t: &termios) -> speed_t { t.c_cflag & CBAUD }
/// # C: speed_t cfgetispeed(const struct termios *)
pub(crate) fn cfgetispeed_of(t: &termios) -> speed_t { t.c_ispeed }

/// Set output speed; rejects baud bits outside CBAUD. Returns 0/-1.
/// # C: int cfsetospeed(struct termios *, speed_t)
pub(crate) fn cfsetospeed_into(t: &mut termios, speed: speed_t) -> i32 {
    if speed & !CBAUD != 0 { return -1; }
    t.c_cflag = (t.c_cflag & !CBAUD) | speed;
    t.c_ospeed = speed;
    0
}
/// # C: int cfsetispeed(struct termios *, speed_t)
pub(crate) fn cfsetispeed_into(t: &mut termios, speed: speed_t) -> i32 {
    if speed & !CBAUD != 0 { return -1; }
    t.c_ispeed = speed; // B0 (0) means "same as output" per POSIX
    0
}

#[cfg(feature = "freestanding")]
pub use imp::*;

#[cfg(feature = "freestanding")]
mod imp {
    use super::*;
    use crate::arch::syscall::sys3;
    use crate::internal::errno::ret_isize;
    use crate::internal::nr;

    // ioctl request numbers (arch-independent on Linux for these).
    const TCGETS: usize = 0x5401; const TCSETS: usize = 0x5402;
    const TCSETSW: usize = 0x5403; const TCSETSF: usize = 0x5404;
    const TCSBRK: usize = 0x5409; const TCXONC: usize = 0x540A;
    const TCFLSH: usize = 0x540B; const TIOCGSID: usize = 0x5429;
    // optional_actions
    const TCSADRAIN: i32 = 1; const TCSAFLUSH: i32 = 2;

    fn ioctl(fd: i32, req: usize, arg: usize) -> i32 {
        // SAFETY: terminal ioctls take an fd + a pointer/scalar arg; the caller
        // guarantees `arg` matches `req` (a termios*, or a small integer).
        ret_isize(unsafe { sys3(nr::IOCTL, fd as usize, req, arg) }) as i32
    }

    // # C: int tcgetattr(int fd, struct termios *t)
    #[no_mangle]
    pub unsafe extern "C" fn tcgetattr(fd: i32, t: *mut termios) -> i32 { ioctl(fd, TCGETS, t as usize) }

    // # C: int tcsetattr(int fd, int optional_actions, const struct termios *t)
    #[no_mangle]
    pub unsafe extern "C" fn tcsetattr(fd: i32, optional_actions: i32, t: *const termios) -> i32 {
        let req = match optional_actions { TCSADRAIN => TCSETSW, TCSAFLUSH => TCSETSF, _ => TCSETS };
        ioctl(fd, req, t as usize)
    }

    // # C: int tcsendbreak(int fd, int duration)
    #[no_mangle]
    pub extern "C" fn tcsendbreak(fd: i32, duration: i32) -> i32 { ioctl(fd, TCSBRK, duration as usize) }
    // # C: int tcdrain(int fd)
    #[no_mangle]
    pub extern "C" fn tcdrain(fd: i32) -> i32 { ioctl(fd, TCSBRK, 1) }
    // # C: int tcflush(int fd, int queue_selector)
    #[no_mangle]
    pub extern "C" fn tcflush(fd: i32, queue: i32) -> i32 { ioctl(fd, TCFLSH, queue as usize) }
    // # C: int tcflow(int fd, int action)
    #[no_mangle]
    pub extern "C" fn tcflow(fd: i32, action: i32) -> i32 { ioctl(fd, TCXONC, action as usize) }
    // # C: pid_t tcgetsid(int fd)
    #[no_mangle]
    pub unsafe extern "C" fn tcgetsid(fd: i32) -> i32 {
        // SAFETY: TIOCGSID writes the session id into a local pid_t.
        let mut sid: i32 = 0;
        let r = ioctl(fd, TIOCGSID, &mut sid as *mut i32 as usize);
        if r < 0 { -1 } else { sid }
    }

    // # C: void cfmakeraw(struct termios *t)
    #[no_mangle]
    pub unsafe extern "C" fn cfmakeraw(t: *mut termios) {
        // SAFETY: t is a valid, initialised termios.
        unsafe { cfmakeraw_into(&mut *t); }
    }
    // # C: speed_t cfgetospeed(const struct termios *t)
    #[no_mangle]
    pub unsafe extern "C" fn cfgetospeed(t: *const termios) -> speed_t {
        // SAFETY: t is a valid, initialised termios; read its output speed.
        unsafe { cfgetospeed_of(&*t) }
    }
    // # C: speed_t cfgetispeed(const struct termios *t)
    #[no_mangle]
    pub unsafe extern "C" fn cfgetispeed(t: *const termios) -> speed_t {
        // SAFETY: t is a valid, initialised termios; read its input speed.
        unsafe { cfgetispeed_of(&*t) }
    }
    // # C: int cfsetospeed(struct termios *t, speed_t speed)
    #[no_mangle]
    pub unsafe extern "C" fn cfsetospeed(t: *mut termios, speed: speed_t) -> i32 {
        // SAFETY: t is a valid, writable termios; set its output speed.
        unsafe { cfsetospeed_into(&mut *t, speed) }
    }
    // # C: int cfsetispeed(struct termios *t, speed_t speed)
    #[no_mangle]
    pub unsafe extern "C" fn cfsetispeed(t: *mut termios, speed: speed_t) -> i32 {
        // SAFETY: t is a valid, writable termios; set its input speed.
        unsafe { cfsetispeed_into(&mut *t, speed) }
    }
    // # C: int cfsetspeed(struct termios *t, speed_t speed)
    #[no_mangle]
    pub unsafe extern "C" fn cfsetspeed(t: *mut termios, speed: speed_t) -> i32 {
        // SAFETY: t is a valid termios; set both input and output speed.
        unsafe { let a = cfsetospeed_into(&mut *t, speed); let b = cfsetispeed_into(&mut *t, speed); if a | b != 0 { -1 } else { 0 } }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zeroed() -> termios {
        termios { c_iflag: 0, c_oflag: 0, c_cflag: 0, c_lflag: 0, c_line: 0, c_cc: [0; NCCS], c_ispeed: 0, c_ospeed: 0 }
    }

    #[test]
    fn termios_abi() { assert_eq!(core::mem::size_of::<termios>(), core::mem::size_of::<libc::termios>()); }

    #[test]
    fn cfmakeraw_clears_canon_echo_sets_cs8() {
        let mut t = zeroed();
        t.c_lflag = ICANON | ECHO | ISIG;
        t.c_oflag = OPOST;
        t.c_iflag = ICRNL | IXON;
        cfmakeraw_into(&mut t);
        assert_eq!(t.c_lflag & (ICANON | ECHO | ISIG), 0);
        assert_eq!(t.c_oflag & OPOST, 0);
        assert_eq!(t.c_iflag & (ICRNL | IXON), 0);
        assert_eq!(t.c_cflag & CS8, CS8);
        assert_eq!(t.c_cc[VMIN], 1);
        assert_eq!(t.c_cc[VTIME], 0);
    }

    #[test]
    fn speed_roundtrip() {
        let mut t = zeroed();
        const B9600: speed_t = 0o000015;
        const B4800: speed_t = 0o000014;
        assert_eq!(cfsetospeed_into(&mut t, B9600), 0);
        assert_eq!(cfgetospeed_of(&t), B9600);
        assert_eq!(cfsetispeed_into(&mut t, B4800), 0);
        assert_eq!(cfgetispeed_of(&t), B4800);
        // out-of-range baud rejected
        assert_eq!(cfsetospeed_into(&mut t, 0x1_0000), -1);
    }
}
