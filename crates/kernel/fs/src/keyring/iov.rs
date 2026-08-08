// `KEYCTL_INSTANTIATE_IOV`'s gather — `import_iovec` + `copy_from_user` — with
// the user-memory primitives passed in.
//
// The rule this file exists to hold is an ORDERING rule, and ordering rules are
// exactly what a test that calls the op core with kernel-owned data cannot see:
// every segment is validated BEFORE any byte is copied, so a bad pointer in the
// last segment leaves NO partial payload behind. Instantiate the key with a
// half-gathered payload and the requester gets a truncated credential and no
// error, which is worse than the EFAULT it should have got.
//
// The validator and the reader are parameters rather than direct calls, so the
// order can be driven — and broken — from a hosted test. The syscall entry
// supplies the real `validate_user_buf` and the real byte read.

use alloc::vec::Vec;
use syscall::errno::Errno;

use super::uapi::KEY_MAX_PAYLOAD;

/// `sizeof(struct iovec)` — `void *iov_base; size_t iov_len;`.
pub const IOVEC_SIZE: u64 = 16;
/// Offset of `iov_len` within one segment.
pub const IOVEC_LEN_OFFSET: u64 = 8;
/// Both fields are pointer-sized, so the array is pointer-aligned.
pub const IOVEC_ALIGN: u64 = 8;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// The user-memory operations the gather needs, so the gather itself owns no
/// unsafe code and can be driven by a test.
pub trait UserMem {
    /// `access_ok` for `[base, base+len)` with `align` alignment. # C: O(1)
    fn validate(&mut self, base: u64, len: u64, align: u64) -> Result<(), i64>;
    /// One `unsigned long` out of the already-validated iovec array. Fallible
    /// because the read itself can fault: validation happened at an earlier
    /// instant and nothing pins the mapping in between. # C: O(1)
    fn read_word(&mut self, at: u64) -> Result<u64, i64>;
    /// Append `len` bytes from `base` to `out`. Called ONLY after every
    /// segment has been validated. # C: O(len)
    fn copy_in(&mut self, base: u64, len: u64, out: &mut Vec<u8>) -> Result<(), i64>;
}

/// Gather `n` segments starting at `p` into one payload.
///
/// Order, and why each step is where it is:
///   1. the ARRAY itself is validated, because reading a segment descriptor is
///      already a user access;
///   2. every segment's length is accumulated and checked against the same
///      1 MiB ceiling `KEYCTL_INSTANTIATE` applies, so a vectored call is not
///      a way around it — `EINVAL`, before any pointer is touched;
///   3. every segment's buffer is validated, `EFAULT` on the first that is not;
///   4. only then is anything copied.
///
/// A zero-length segment is dropped rather than validated: the ABI lets a
/// caller pass a NULL base with a zero length, and faulting on it would reject
/// a legal vector.
/// # C: O(n + total)
pub fn gather(m: &mut dyn UserMem, p: u64, n: u64) -> Result<Vec<u8>, i64> {
    if n == 0 { return Ok(Vec::new()); }
    let array_bytes = n.checked_mul(IOVEC_SIZE).ok_or(err(Errno::Efault))?;
    m.validate(p, array_bytes, IOVEC_ALIGN)?;
    let mut segs: Vec<(u64, u64)> = Vec::new();
    let mut total: u64 = 0;
    for i in 0..n {
        let e = p + i * IOVEC_SIZE;
        let base = m.read_word(e)?;
        let len = m.read_word(e + IOVEC_LEN_OFFSET)?;
        if len == 0 { continue; }
        total = total.checked_add(len).ok_or(err(Errno::Einval))?;
        if total > KEY_MAX_PAYLOAD { return Err(err(Errno::Einval)); }
        m.validate(base, len, 1)?;
        segs.push((base, len));
    }
    let mut out = Vec::with_capacity(total as usize);
    for (base, len) in segs { m.copy_in(base, len, &mut out)?; }
    Ok(out)
}

#[cfg(test)] mod tests;
