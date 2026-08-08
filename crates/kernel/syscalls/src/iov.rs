// `import_iovec()` — the one place a `struct iovec`
// array is read out of user memory and turned into a validated segment list.
//
// Both directions share it so the READ and WRITE sides cannot drift: the write
// side used to walk the array inline with none of the importer's rules, which
// is how `pwritev` ended up without the negative-length `EINVAL`, without the
// `MAX_RW_COUNT` truncation, and — worst — validating segment `i` only after
// segment `i-1` had already been written, so a bad pointer late in the vector
// returned `EFAULT` on top of a partially completed write.
//
// The RULES live in `crate::rwf::iov_import_seg` (ungated, hosted-tested); this
// module is only the usercopy that feeds them.

#![cfg(target_os = "oxide-kernel")]

use alloc::vec::Vec;
use syscall::errno::Errno;

use crate::rwf::{iov_import_seg, IovSeg, UIO_MAXIOV};
use crate::userbuf::{validate_user_buf, validate_user_buf_writable};

/// Bytes per `struct iovec` (`void *iov_base; size_t iov_len;`) on both
/// 64-bit targets, and the alignment the ABI guarantees.
const IOVEC_SIZE: u64  = 16;
const IOVEC_ALIGN: u64 = 8;
/// Offset of `iov_len` inside `struct iovec`.
const IOVEC_LEN_OFF: u64 = 8;

/// Direction the imported segments will be used in: a destination vector must
/// be provably WRITABLE, a source vector only readable.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum IovDir { Dest, Source }

/// `import_iovec()`: validate the iovec array itself, then every segment, in
/// full, BEFORE any I/O happens. Returns the accepted `(base, len)` list.
///
/// `iovcnt == 0` is a legal zero-length operation returning an empty list, not
/// an error; `iovcnt > UIO_MAXIOV` is `EINVAL`. # C: O(iovcnt)
pub fn import_iovec(iov: u64, iovcnt: u64, dir: IovDir) -> Result<Vec<(u64, usize)>, i64> {
    let mut out: Vec<(u64, usize)> = Vec::new();
    if iovcnt > UIO_MAXIOV { return Err(-(Errno::Einval.as_i32() as i64)); }
    if iovcnt == 0 { return Ok(out); }
    let array_bytes = iovcnt.checked_mul(IOVEC_SIZE).ok_or(-(Errno::Efault.as_i32() as i64))?;
    validate_user_buf(iov, array_bytes, IOVEC_ALIGN)?;
    let mut total: u64 = 0;
    for i in 0..iovcnt {
        let iov_i = iov + i * IOVEC_SIZE;
        // SAFETY: `validate_user_buf` proved the whole iovec array readable in
        // the active address space; `iov_i` is inside it and 8-byte aligned.
        let base = unsafe { core::ptr::read_volatile(iov_i as *const u64) };
        // SAFETY: same validated array; `iov_len` sits at +8 within the entry.
        let len  = unsafe { core::ptr::read_volatile((iov_i + IOVEC_LEN_OFF) as *const u64) };
        let take = match iov_import_seg(len, total) {
            Ok(IovSeg::Skip)    => continue,
            Ok(IovSeg::Stop)    => break,
            Ok(IovSeg::Take(n)) => n,
            Err(e)              => return Err(-(e.as_i32() as i64)),
        };
        // The FULL declared segment is validated, not just the accepted prefix:
        // Linux's `iovec_from_user` faults on the whole entry.
        match dir {
            IovDir::Dest   => validate_user_buf_writable(base, len, 1)?,
            IovDir::Source => validate_user_buf(base, len, 1)?,
        }
        total += take;
        out.push((base, take as usize));
    }
    Ok(out)
}
