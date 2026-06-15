// 64-bit resource limits + legacy ulimit (docs/59§6 G8). getrlimit64/
// setrlimit64 are byte-identical aliases of getrlimit/setrlimit (rlim_t is
// already 64-bit on Linux); ulimit() is the SysV legacy over getrlimit.
#![cfg(feature = "freestanding")]
use crate::posix::resource::{Rlimit, getrlimit, setrlimit};
use core::ffi::VaList;

const RLIMIT_FSIZE: i32 = 1; // file-size limit, in bytes
// ulimit() returns/takes block units (512 B); UL_GETFSIZE/UL_SETFSIZE per cmd.
const UL_GETFSIZE: i32 = 1;
const UL_SETFSIZE: i32 = 2;
const BLOCK: u64 = 512;

// # C: int getrlimit64(int resource, struct rlimit64 *rlim)
#[no_mangle]
pub unsafe extern "C" fn getrlimit64(resource: i32, rlim: *mut Rlimit) -> i32 {
    // SAFETY: rlimit64 == rlimit on Linux (rlim_t is u64); forwards directly.
    unsafe { getrlimit(resource, rlim) }
}
// # C: int setrlimit64(int resource, const struct rlimit64 *rlim)
#[no_mangle]
pub unsafe extern "C" fn setrlimit64(resource: i32, rlim: *const Rlimit) -> i32 {
    // SAFETY: rlimit64 == rlimit on Linux; forwards directly.
    unsafe { setrlimit(resource, rlim) }
}

// # C: long ulimit(int cmd, ...)
#[no_mangle]
pub unsafe extern "C" fn ulimit(cmd: i32, mut ap: ...) -> i64 {
    // SAFETY: ulimit(3) over RLIMIT_FSIZE. UL_GETFSIZE reads rlim_cur (in 512 B
    // blocks); UL_SETFSIZE consumes one long vararg and sets the limit. The
    // varargs are well-formed per the documented cmd contract.
    unsafe { do_ulimit(cmd, &mut ap) }
}

unsafe fn do_ulimit(cmd: i32, ap: &mut VaList) -> i64 {
    // SAFETY: helper for ulimit; reads/writes a stack Rlimit and one vararg.
    unsafe {
        let mut rl = Rlimit { rlim_cur: 0, rlim_max: 0 };
        match cmd {
            UL_GETFSIZE => {
                if getrlimit(RLIMIT_FSIZE, &mut rl) != 0 { return -1; }
                if rl.rlim_cur == u64::MAX { i64::MAX } else { (rl.rlim_cur / BLOCK) as i64 }
            }
            UL_SETFSIZE => {
                let blocks = ap.next_arg::<i64>() as u64;
                rl.rlim_cur = blocks.saturating_mul(BLOCK);
                rl.rlim_max = rl.rlim_cur;
                if setrlimit(RLIMIT_FSIZE, &rl) != 0 { return -1; }
                (rl.rlim_cur / BLOCK) as i64
            }
            _ => -1,
        }
    }
}
