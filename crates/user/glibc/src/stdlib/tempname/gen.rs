// Shared temp-name loop — glibc sysdeps/posix/tempname.c `try_tempname_len`.
// Validates the template's trailing "XXXXXX", rewrites it with base-62 letters
// drawn from getrandom(2), and calls `tryfunc` (open / mkdir / existence
// probe) until it stops answering EEXIST or the ATTEMPTS budget runs out.
#![cfg(feature = "freestanding")]
use super::entropy::random_bits;
use super::value::{needs_redraw, DigitPool, ATTEMPTS, X_SUFFIX_LEN};
use crate::internal::errno;
use crate::string::len::strlen_impl;

const EINVAL: i32 = 22;
pub(crate) const EEXIST: i32 = 17;

// One draw honouring glibc's bias rejection: redraw while the value is high
// quality AND ≥ biased_min, chaining the previous value into the ersatz path.
fn fresh_value(prev: &mut u64) -> u64 {
    loop {
        let (v, hq) = random_bits(*prev);
        *prev = v;
        if !needs_redraw(hq, v) { return v; }
    }
}

/// # C: try_tempname_len(tmpl, suffixlen, args, tryfunc, 6)
/// `tryfunc` returns a raw syscall result: ≥0 on success, -errno otherwise.
/// Returns that success value, or -1 with errno set. glibc restores the
/// entry errno on success; our `tryfunc`s issue raw syscalls that never touch
/// errno, so it is already untouched on the success path.
pub(crate) unsafe fn try_tempname<F: FnMut(*mut u8) -> isize>(tmpl: *mut u8, suffixlen: usize, mut tryfunc: F) -> isize {
    // SAFETY: caller guarantees tmpl is a writable NUL-terminated C string; we
    // rewrite only the X_SUFFIX_LEN bytes first verified to be all 'X'.
    unsafe {
        let len = strlen_impl(tmpl);
        if len < X_SUFFIX_LEN + suffixlen { errno::set(EINVAL); return -1; }
        let xs = tmpl.add(len - X_SUFFIX_LEN - suffixlen);
        for k in 0..X_SUFFIX_LEN { if *xs.add(k) != b'X' { errno::set(EINVAL); return -1; } }

        let mut pool = DigitPool::new();
        let mut prev = 0u64;
        for _ in 0..ATTEMPTS {
            for k in 0..X_SUFFIX_LEN {
                if pool.is_empty() { pool.refill(fresh_value(&mut prev)); }
                *xs.add(k) = pool.next_letter();
            }
            let rc = tryfunc(tmpl);
            if rc >= 0 { return rc; }
            if rc != -(EEXIST as isize) { errno::set(-rc as i32); return -1; }
        }
        errno::set(EEXIST);
        -1
    }
}
