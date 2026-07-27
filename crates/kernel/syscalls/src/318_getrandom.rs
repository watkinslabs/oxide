// 318 getrandom — one syscall, one file (docs/53 §0).

use syscall::errno::Errno;
use syscall::getrandom::{validate_grnd_flags, GETRANDOM_COUNT_MAX};
use syscall::SyscallArgs;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// `sys_getrandom(buf, len, flags)` — slot 318. Fills `buf` from the HW RNG
/// (falls back to the kernel LCG), 8 bytes at a time.
///
/// Flags per Linux `getrandom(2)`: unknown bits and `GRND_RANDOM|GRND_INSECURE`
/// together are `EINVAL` (`syscall::getrandom::validate_grnd_flags`). This
/// kernel's entropy source (RDRAND/RNDR, LCG fallback —
/// `crates/kernel/syscalls/src/hwrng.rs`) has no boot-time "pool not ready"
/// state — it is always considered initialised — so `GRND_NONBLOCK` never
/// needs to return `EAGAIN` and none of the three flags change the fill path
/// beyond validation; they are still validated because rejecting unknown
/// bits/combinations is itself observable Linux ABI behaviour.
/// # C: O(len)
pub fn sys_getrandom(args: &SyscallArgs) -> i64 {
    let buf = args.a0;
    // Linux clamps count to INT_MAX before touching the buffer (signed
    // ssize_t return); flags are the low 32 bits of the raw register arg.
    let len = args.a1.min(GETRANDOM_COUNT_MAX);
    let flags = args.a2 as u32;
    if let Err(e) = validate_grnd_flags(flags) { return err(e); }
    if len == 0 { return 0; }
    if let Err(rv) = crate::userbuf::validate_user_buf_writable(buf, len, 1) { return rv; }
    let mut written: u64 = 0;
    while written < len {
        let v = crate::hwrng::hw_random_u64().unwrap_or_else(::devfs::misc::lcg_next).to_le_bytes();
        let n = (len - written).min(8);
        // SAFETY: full [buf, buf + len) span was validated writable; byte stores are alignment-independent.
        unsafe { for i in 0..n { core::ptr::write_unaligned((buf + written + i) as *mut u8, v[i as usize]); } }
        written += n;
    }
    written as i64
}
