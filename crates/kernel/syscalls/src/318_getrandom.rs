// 318 getrandom — one syscall, one file (docs/53 §0).

use syscall::errno::Errno;
use syscall::getrandom::{validate_grnd_flags, GETRANDOM_COUNT_MAX, GRND_INSECURE, GRND_NONBLOCK};
use syscall::SyscallArgs;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// `sys_getrandom(buf, len, flags)` — slot 318. Fills `buf` from the kernel
/// CSPRNG (`crng`: ChaCha20 with fast key erasure, seeded from virtio-rng /
/// RDRAND / RNDR plus cycle-counter jitter — Linux
/// `drivers/char/random.c`'s construction).
///
/// Flags per Linux `getrandom(2)`: unknown bits and `GRND_RANDOM|GRND_INSECURE`
/// together are `EINVAL` (`syscall::getrandom::validate_grnd_flags`).
/// `GRND_RANDOM` and `GRND_INSECURE` select the same generator, exactly as on
/// Linux since 5.6 — `/dev/random` and `/dev/urandom` were unified there and
/// `GRND_RANDOM` became a no-op.
///
/// `GRND_NONBLOCK` returns `EAGAIN` while the pool is uninitialised. The pool
/// seeds itself on first use from every source present, so this is reachable
/// only if no source at all answered; it is wired rather than assumed away so
/// the flag reports the truth instead of a fixed "always ready".
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
    if !crng::is_initialized() {
        crng::reseed();
        if !crng::is_initialized()
            && (flags & (GRND_NONBLOCK | GRND_INSECURE)) != 0 { return err(Errno::Eagain); }
    }
    // Chunked through a kernel buffer so the CSPRNG output never has to be
    // produced directly into a user page.
    const CHUNK: usize = 256;
    let mut scratch = [0u8; CHUNK];
    let mut written: u64 = 0;
    while written < len {
        let n = core::cmp::min(CHUNK as u64, len - written) as usize;
        crng::fill(&mut scratch[..n]);
        if uaccess::copy_to_user(buf + written, &scratch[..n]).is_err() {
            // Linux returns the short count when some bytes already landed.
            return if written > 0 { written as i64 } else { err(Errno::Efault) };
        }
        written += n as u64;
    }
    written as i64
}
