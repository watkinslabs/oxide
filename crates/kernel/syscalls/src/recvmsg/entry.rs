// Native recvmsg entry admission — reject compat-only flags before user-visible work.

use net::uapi::MSG_CMSG_COMPAT;
use syscall::errno::Errno;

fn err(error: Errno) -> i64 { -(error.as_i32() as i64) }

/// Apply Linux native recvmsg flag admission before descriptor or user-memory access. # C: O(1)
pub(crate) fn prepare<T, U>(flags: u64, lookup: impl FnOnce() -> Result<T, i64>,
    import: impl FnOnce() -> Result<U, i64>) -> Result<(T, U), i64>
{
    if flags & MSG_CMSG_COMPAT != 0 { return Err(err(Errno::Einval)); }
    Ok((lookup()?, import()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU8, Ordering};
    use net::uapi::MSG_CMSG_CLOEXEC;

    const LOOKUP_CALLED: u8 = 1;
    const IMPORT_CALLED: u8 = 2;

    #[test]
    fn cmsg_compat_precedes_invalid_fd_and_msghdr() {
        let calls = AtomicU8::new(0);
        let result: Result<((), ()), i64> = prepare(MSG_CMSG_COMPAT,
            || { calls.fetch_or(LOOKUP_CALLED, Ordering::Relaxed); Err(Errno::Ebadf.as_i32() as i64) },
            || { calls.fetch_or(IMPORT_CALLED, Ordering::Relaxed); Err(Errno::Efault.as_i32() as i64) });
        assert_eq!(result, Err(err(Errno::Einval)));
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn cmsg_cloexec_keeps_normal_lookup_and_import_order() {
        let calls = AtomicU8::new(0);
        let result = prepare(MSG_CMSG_CLOEXEC,
            || { calls.fetch_or(LOOKUP_CALLED, Ordering::Relaxed); Ok::<_, i64>("fd") },
            || { calls.fetch_or(IMPORT_CALLED, Ordering::Relaxed); Ok::<_, i64>("msghdr") });
        assert_eq!(result, Ok(("fd", "msghdr")));
        assert_eq!(calls.load(Ordering::Relaxed), LOOKUP_CALLED | IMPORT_CALLED);
    }
}
