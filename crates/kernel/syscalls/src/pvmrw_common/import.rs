// Fetching an iovec array out of the CALLER's address space, Linux
// `copy_iovec_from_user` + `iovec_from_user`.

use alloc::vec::Vec;
use syscall::errno::Errno;

use super::decide;
use crate::userbuf::validate_user_buf_readable;

/// Fetch `n` `struct iovec` records from the caller's address space at `p`.
///
/// Linux order (`iovec_from_user` → `copy_iovec_from_user`): the segment
/// COUNT is rejected first (EINVAL, without touching `p`), then the whole
/// array is copied in one `user_access_begin` window (EFAULT), then every
/// segment's length is checked against `ssize_t` (EINVAL). Address
/// validation of the segments themselves is NOT done here — it is
/// local-array-only and lives in `decide::import_local`, because the remote
/// array's addresses are never `access_ok`-checked at all.
/// # C: O(n)
pub(crate) fn read_iovs(p: u64, n: usize) -> Result<Vec<(u64, u64)>, i64> {
    decide::check_seg_count(n)?;
    if n == 0 { return Ok(Vec::new()); }
    let bytes = n * decide::IOVEC_BYTES;
    validate_user_buf_readable(p, bytes as u64, 1)?;
    let mut raw = alloc::vec![0u8; bytes];
    uaccess::copy_from_user(&mut raw[..], p)
        .map_err(|_| -(Errno::Efault.as_i32() as i64))?;
    let mut out = Vec::with_capacity(n);
    for i in 0..n { out.push(decide::decode_iov(&raw[..], i)); }
    decide::check_all_seg_lens(&out[..])?;
    Ok(out)
}
