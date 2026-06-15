// <sys/timex.h> (docs/59§6) — adjtimex/clock_adjtime syscall wrappers plus the
// xntp aliases ntp_adjtime/ntp_gettime and the legacy adjtime(2). struct timex
// matches the host bits/timex.h 64-bit layout (208 bytes, all-i64 fields +
// i32 status/shift/tai with padding). C ABI only.
#![cfg(feature = "freestanding")]
use crate::arch::syscall::{sys1, sys2};
use crate::internal::errno::{ret_isize, set};
use crate::internal::nr;
use crate::time::clock::timeval;

pub const ADJ_OFFSET_SINGLESHOT: u32 = 0x8001; // legacy adjtime: set offset, one-shot
const EFAULT: i32 = 14;

#[repr(C)]
pub struct timex {
    pub modes: u32, __pad0: u32,
    pub offset: i64, pub freq: i64, pub maxerror: i64, pub esterror: i64,
    pub status: i32, __pad1: u32,
    pub constant: i64, pub precision: i64, pub tolerance: i64,
    pub time: timeval,
    pub tick: i64, pub ppsfreq: i64, pub jitter: i64,
    pub shift: i32, __pad2: u32,
    pub stabil: i64, pub jitcnt: i64, pub calcnt: i64, pub errcnt: i64, pub stbcnt: i64,
    pub tai: i32,
    __pad3: [i32; 11],
}
const _: () = {
    assert!(core::mem::offset_of!(timex, offset) == 8);
    assert!(core::mem::offset_of!(timex, freq) == 16);
    assert!(core::mem::offset_of!(timex, status) == 40);
    assert!(core::mem::offset_of!(timex, constant) == 48);
    assert!(core::mem::offset_of!(timex, time) == 72);
    assert!(core::mem::offset_of!(timex, tick) == 88);
    assert!(core::mem::offset_of!(timex, tai) == 160);
    assert!(core::mem::size_of::<timex>() == 208);
};

// struct ntptimeval (host: 72 bytes — timeval time; long maxerror/esterror/tai;
// 4× long reserved).
#[repr(C)]
pub struct ntptimeval {
    pub time: timeval,
    pub maxerror: i64, pub esterror: i64, pub tai: i64,
    __res: [i64; 4],
}
const _: () = {
    assert!(core::mem::offset_of!(ntptimeval, maxerror) == 16);
    assert!(core::mem::offset_of!(ntptimeval, tai) == 32);
    assert!(core::mem::size_of::<ntptimeval>() == 72);
};

// adjtimex(2): kernel returns the clock state (TIME_OK=0..TIME_ERROR=5) on
// success or -errno; glibc passes the state through and only -1/EINVAL'ing on
// error. The state band is non-negative so ret_isize handles errno correctly.
// # C: int adjtimex(struct timex *buf)
#[no_mangle]
pub unsafe extern "C" fn adjtimex(buf: *mut timex) -> i32 {
    // SAFETY: buf is a valid struct timex per adjtimex(2); the kernel reads
    // .modes and writes the disciplined fields back in place.
    ret_isize(unsafe { sys1(nr::ADJTIMEX, buf as usize) }) as i32
}

// # C: int ntp_adjtime(struct timex *buf)
#[no_mangle]
pub unsafe extern "C" fn ntp_adjtime(buf: *mut timex) -> i32 {
    // SAFETY: ntp_adjtime is the xntp alias of adjtimex; forward verbatim.
    unsafe { adjtimex(buf) }
}

// # C: int clock_adjtime(clockid_t clk, struct timex *buf)
#[no_mangle]
pub unsafe extern "C" fn clock_adjtime(clk: i32, buf: *mut timex) -> i32 {
    // SAFETY: buf is a valid struct timex; clk selects the clock to discipline.
    ret_isize(unsafe { sys2(nr::CLOCK_ADJTIME, clk as usize, buf as usize) }) as i32
}

// # C: int ntp_gettime(struct ntptimeval *ntv)
#[no_mangle]
pub unsafe extern "C" fn ntp_gettime(ntv: *mut ntptimeval) -> i32 {
    // SAFETY: ntv is a valid ntptimeval out-param; we issue a read-only
    // adjtimex (modes=0) into a local timex and copy the relevant fields out.
    unsafe { ntp_gettimex(ntv) }
}

// # C: int ntp_gettimex(struct ntptimeval *ntv)
#[no_mangle]
pub unsafe extern "C" fn ntp_gettimex(ntv: *mut ntptimeval) -> i32 {
    // SAFETY: ntv is a valid ntptimeval out-param; a read-only adjtimex fills a
    // local timex whose time/maxerror/esterror/tai we forward into *ntv.
    unsafe {
        if ntv.is_null() { set(EFAULT); return -1; }
        let mut tx: timex = core::mem::zeroed();
        let r = adjtimex(&mut tx);
        if r < 0 { return r; }
        (*ntv).time = timeval { tv_sec: tx.time.tv_sec, tv_usec: tx.time.tv_usec };
        (*ntv).maxerror = tx.maxerror;
        (*ntv).esterror = tx.esterror;
        (*ntv).tai = tx.tai as i64;
        r
    }
}

// # C: int adjtime(const struct timeval *delta, struct timeval *olddelta)
#[no_mangle]
pub unsafe extern "C" fn adjtime(delta: *const timeval, olddelta: *mut timeval) -> i32 {
    // SAFETY: delta is null or a valid timeval; olddelta is null or writable.
    // Emulate legacy adjtime via a single-shot adjtimex (glibc sysdeps path):
    // set offset in usec when delta!=null, read prior offset back into olddelta.
    unsafe {
        let mut tx: timex = core::mem::zeroed();
        if !delta.is_null() {
            tx.modes = ADJ_OFFSET_SINGLESHOT;
            tx.offset = (*delta).tv_sec * 1_000_000 + (*delta).tv_usec;
        }
        let r = adjtimex(&mut tx);
        if r < 0 { return -1; }
        if !olddelta.is_null() {
            (*olddelta).tv_sec = tx.offset / 1_000_000;
            (*olddelta).tv_usec = tx.offset % 1_000_000;
        }
        0
    }
}
