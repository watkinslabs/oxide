// strsignal(3) (docs/59§6 G9): signal number → description (C locale, matching
// glibc's Linux strings). Standard 1–31 return 'static literals; out-of-range
// values format "Unknown signal N" / real-time signals into a process-global
// buffer. C ABI only.
#![cfg(feature = "freestanding")]
use core::cell::UnsafeCell;

fn known(sig: i32) -> Option<&'static [u8]> {
    Some(match sig {
        1 => b"Hangup\0",
        2 => b"Interrupt\0",
        3 => b"Quit\0",
        4 => b"Illegal instruction\0",
        5 => b"Trace/breakpoint trap\0",
        6 => b"Aborted\0",
        7 => b"Bus error\0",
        8 => b"Floating point exception\0",
        9 => b"Killed\0",
        10 => b"User defined signal 1\0",
        11 => b"Segmentation fault\0",
        12 => b"User defined signal 2\0",
        13 => b"Broken pipe\0",
        14 => b"Alarm clock\0",
        15 => b"Terminated\0",
        16 => b"Stack fault\0",
        17 => b"Child exited\0",
        18 => b"Continued\0",
        19 => b"Stopped (signal)\0",
        20 => b"Stopped\0",
        21 => b"Stopped (tty input)\0",
        22 => b"Stopped (tty output)\0",
        23 => b"Urgent I/O condition\0",
        24 => b"CPU time limit exceeded\0",
        25 => b"File size limit exceeded\0",
        26 => b"Virtual timer expired\0",
        27 => b"Profiling timer expired\0",
        28 => b"Window changed\0",
        29 => b"I/O possible\0",
        30 => b"Power failure\0",
        31 => b"Bad system call\0",
        _ => return None,
    })
}

// Signal abbreviation (no "SIG" prefix) for the standard 1–31 signals; glibc's
// sys_sigabbrev. NULL for RT / out-of-range. SIGABRT(6)=ABRT, SIGIO/POLL(29)=POLL.
fn abbrev(sig: i32) -> Option<&'static [u8]> {
    Some(match sig {
        1 => b"HUP\0", 2 => b"INT\0", 3 => b"QUIT\0", 4 => b"ILL\0", 5 => b"TRAP\0",
        6 => b"ABRT\0", 7 => b"BUS\0", 8 => b"FPE\0", 9 => b"KILL\0", 10 => b"USR1\0",
        11 => b"SEGV\0", 12 => b"USR2\0", 13 => b"PIPE\0", 14 => b"ALRM\0", 15 => b"TERM\0",
        16 => b"STKFLT\0", 17 => b"CHLD\0", 18 => b"CONT\0", 19 => b"STOP\0", 20 => b"TSTP\0",
        21 => b"TTIN\0", 22 => b"TTOU\0", 23 => b"URG\0", 24 => b"XCPU\0", 25 => b"XFSZ\0",
        26 => b"VTALRM\0", 27 => b"PROF\0", 28 => b"WINCH\0", 29 => b"POLL\0", 30 => b"PWR\0",
        31 => b"SYS\0",
        _ => return None,
    })
}

// # C: const char *sigabbrev_np(int sig)
#[no_mangle]
pub extern "C" fn sigabbrev_np(sig: i32) -> *const u8 {
    match abbrev(sig) { Some(a) => a.as_ptr(), None => core::ptr::null() }
}

// # C: const char *sigdescr_np(int sig)
#[no_mangle]
pub extern "C" fn sigdescr_np(sig: i32) -> *const u8 {
    match known(sig) { Some(d) => d.as_ptr(), None => core::ptr::null() }
}

struct Buf(UnsafeCell<[u8; 32]>);
// SAFETY: process-global strsignal scratch for the unknown/RT path; single
// threaded until TLS makes it per-thread.
unsafe impl Sync for Buf {}
static BUF: Buf = Buf(UnsafeCell::new([0u8; 32]));

// # C: char *strsignal(int sig)
#[no_mangle]
pub extern "C" fn strsignal(sig: i32) -> *mut u8 {
    if let Some(m) = known(sig) { return m.as_ptr() as *mut u8; }
    // SAFETY: write the formatted message into the process-global buffer (≤31
    // bytes + NUL) and return its address, matching glibc's static-buffer path.
    unsafe {
        let b = &mut *BUF.0.get();
        let prefix: &[u8] = if (34..=64).contains(&sig) { b"Real-time signal " } else { b"Unknown signal " };
        let mut n = 0;
        for &c in prefix { b[n] = c; n += 1; }
        // glibc numbers real-time signals from SIGRTMIN (34) as 0..
        let v = if (34..=64).contains(&sig) { sig - 34 } else { sig };
        n += write_int(&mut b[n..], v);
        b[n] = 0;
        b.as_mut_ptr()
    }
}

fn write_int(buf: &mut [u8], v: i32) -> usize {
    let neg = v < 0;
    let mut tmp = [0u8; 12];
    let mut t = 0;
    let mut u = (v as i64).unsigned_abs();
    if u == 0 { tmp[t] = b'0'; t += 1; }
    while u > 0 { tmp[t] = b'0' + (u % 10) as u8; t += 1; u /= 10; }
    let mut n = 0;
    if neg { buf[n] = b'-'; n += 1; }
    while t > 0 { t -= 1; buf[n] = tmp[t]; n += 1; }
    n
}
