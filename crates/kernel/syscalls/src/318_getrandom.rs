// 318 getrandom — one syscall, one file (docs/53 §0).

use syscall::SyscallArgs;

/// `sys_getrandom(buf, len, flags)` — slot 318. Fills `buf` from the HW RNG
/// (falls back to the kernel LCG), 8 bytes at a time.
/// # C: O(len)
pub fn sys_getrandom(args: &SyscallArgs) -> i64 {
    let buf = args.a0;
    let len = args.a1;
    if len == 0 { return 0; }
    if let Err(rv) = crate::validate_user_buf(buf, len, 1) { return rv; }
    let mut written: u64 = 0;
    while written < len {
        let v = crate::hwrng::hw_random_u64().unwrap_or_else(::devfs::misc::lcg_next).to_le_bytes();
        let n = (len - written).min(8);
        // SAFETY: validated [buf,buf+len) below USER_VA_END; CPL=0 writes via caller's AS.
        unsafe { for i in 0..n { core::ptr::write_volatile((buf + written + i) as *mut u8, v[i as usize]); } }
        written += n;
    }
    written as i64
}
