// `UserPtr<T>` / `UserSlice<T>` per `15§1.4`.
//
// Constructed at the dispatch boundary from raw u64 register values;
// validates range (`ptr + bytes ≤ USER_VA_END`) and natural alignment
// once. Past dispatch the kernel never sees a raw `*mut u8`.
//
// PT-validity (the page-fault check per `15§1.4` step 2) is the
// concern of `copy_from_user` / `copy_to_user`, which land alongside
// HAL `MmuOps`. This module covers the range/alignment side only.

use core::marker::PhantomData;
use core::mem::{align_of, size_of};

use hal::{UserVirtAddr, USER_VA_END};

use crate::errno::Errno;

/// Validated user-space pointer to one `T`.
#[derive(Debug, Eq, PartialEq)]
pub struct UserPtr<T> {
    addr: UserVirtAddr,
    _t:   PhantomData<*mut T>,
}

impl<T> UserPtr<T> {
    /// Validate `raw` is page-resident (`< USER_VA_END`), naturally
    /// aligned for `T`, and that the full `size_of::<T>()` byte range
    /// stays inside the user range.
    /// # C: O(1)
    pub fn new(raw: u64) -> Result<Self, Errno> {
        validate_range(raw, size_of::<T>() as u64)?;
        validate_align(raw, align_of::<T>())?;
        // SAFETY of the underlying address newtype is enforced via
        // `UserVirtAddr::new`; the constructor rejects ≥ USER_VA_END.
        let uva = UserVirtAddr::new(raw).ok_or(Errno::Efault)?;
        Ok(Self { addr: uva, _t: PhantomData })
    }

    /// # C: O(1)
    pub fn as_user_va(&self) -> UserVirtAddr { self.addr }

    /// # C: O(1)
    pub fn as_u64(&self) -> u64 { self.addr.as_u64() }
}

impl<T> Copy for UserPtr<T> {}
impl<T> Clone for UserPtr<T> {
    fn clone(&self) -> Self { *self }
}

/// Validated user-space slice of `len` `T`s.
#[derive(Debug, Eq, PartialEq)]
pub struct UserSlice<T> {
    addr: UserVirtAddr,
    len:  usize,
    _t:   PhantomData<*mut T>,
}

impl<T> UserSlice<T> {
    /// Empty slice constructor: `len == 0` is allowed at any address
    /// (including `0`) per Linux's traditional permissiveness.
    /// # C: O(1)
    pub fn new(raw: u64, len: usize) -> Result<Self, Errno> {
        if len == 0 {
            // Empty slice: even null is fine; nothing will be read.
            // `addr` still goes through `UserVirtAddr::new` to keep
            // the type non-canonical-free; raw == 0 succeeds.
            let uva = UserVirtAddr::new(raw.min(USER_VA_END.saturating_sub(1)))
                .ok_or(Errno::Efault)?;
            return Ok(Self { addr: uva, len: 0, _t: PhantomData });
        }
        let bytes = (len as u64).checked_mul(size_of::<T>() as u64).ok_or(Errno::Efault)?;
        validate_range(raw, bytes)?;
        validate_align(raw, align_of::<T>())?;
        let uva = UserVirtAddr::new(raw).ok_or(Errno::Efault)?;
        Ok(Self { addr: uva, len, _t: PhantomData })
    }

    /// # C: O(1)
    pub fn as_user_va(&self) -> UserVirtAddr { self.addr }

    /// # C: O(1)
    pub fn len(&self) -> usize { self.len }

    /// # C: O(1)
    pub fn is_empty(&self) -> bool { self.len == 0 }

    /// Byte length.
    /// # C: O(1)
    pub fn len_bytes(&self) -> u64 {
        (self.len as u64).saturating_mul(size_of::<T>() as u64)
    }
}

/// Copy a NUL-terminated C string out of user memory starting at
/// `base`, one byte at a time via `read`, into an owned `Vec` (NUL
/// excluded). Bounds match Linux `strndup_user(..., max_len)` used by
/// `getname_flags` on the execve path:
///   * first `0` byte terminates → `Ok(bytes_before_nul)`;
///   * reaching `USER_VA_END` before a NUL → `Efault` (the walk ran
///     off the user half into unmapped/non-canonical space);
///   * no NUL within `max_len` bytes → `Enametoolong`.
///
/// Pure over the byte-reader so the length policy is unit-testable
/// off-target (the kernel caller passes a `read_volatile` closure).
/// The caller handles `base == 0` (NULL) before calling.
/// # C: O(max_len)
pub fn scan_user_cstr(
    base: u64,
    max_len: u64,
    mut read: impl FnMut(u64) -> u8,
) -> Result<alloc::vec::Vec<u8>, Errno> {
    if base >= USER_VA_END { return Err(Errno::Efault); }
    let mut out: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    for i in 0..max_len {
        let va = base.checked_add(i).ok_or(Errno::Efault)?;
        if va >= USER_VA_END { return Err(Errno::Efault); }
        let b = read(va);
        if b == 0 { return Ok(out); }
        out.push(b);
    }
    Err(Errno::Enametoolong)
}

#[inline]
fn validate_range(raw: u64, bytes: u64) -> Result<(), Errno> {
    let end = raw.checked_add(bytes).ok_or(Errno::Efault)?;
    if end > USER_VA_END { return Err(Errno::Efault); }
    Ok(())
}

#[inline]
fn validate_align(raw: u64, align: usize) -> Result<(), Errno> {
    if align == 0 { return Ok(()); }
    if raw & ((align as u64) - 1) != 0 { return Err(Errno::Efault); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errno::Errno;

    // Read a C string laid out at a fake `base` from a Rust buffer.
    fn cstr_at(base: u64, bytes: &[u8], max: u64) -> Result<alloc::vec::Vec<u8>, Errno> {
        scan_user_cstr(base, max, |va| bytes[(va - base) as usize])
    }

    #[test]
    fn scan_reads_full_path_not_capped_at_64() {
        // The exact user-session generator that regressed: 79 bytes, well
        // past the old 64-byte cap. Must come back byte-for-byte intact.
        let mut buf =
            b"/usr/lib/systemd/user-environment-generators/30-systemd-environment-d-generator".to_vec();
        assert_eq!(buf.len(), 79);
        buf.push(0); // NUL terminator
        let got = cstr_at(0x1000, &buf, 4096).expect("resolves");
        assert_eq!(got.len(), 79);
        assert_eq!(&got[..], &buf[..79]);
    }

    #[test]
    fn scan_boundary_64_and_65() {
        // 64-byte path terminates fine (was the largest that used to work).
        let mut a = alloc::vec![b'a'; 64]; a.push(0);
        assert_eq!(cstr_at(0x1000, &a, 4096).unwrap().len(), 64);
        // 65-byte path used to be silently truncated → ENOENT; now intact.
        let mut b = alloc::vec![b'b'; 65]; b.push(0);
        assert_eq!(cstr_at(0x1000, &b, 4096).unwrap().len(), 65);
    }

    #[test]
    fn scan_no_nul_within_max_is_enametoolong() {
        // No terminator inside max_len → ENAMETOOLONG (Linux PATH_MAX rule),
        // never a truncated success.
        let buf = alloc::vec![b'x'; 16];
        assert_eq!(cstr_at(0x1000, &buf, 8), Err(Errno::Enametoolong));
    }

    #[test]
    fn scan_base_past_user_end_is_efault() {
        assert_eq!(scan_user_cstr(USER_VA_END, 4096, |_| b'a'), Err(Errno::Efault));
        assert_eq!(scan_user_cstr(USER_VA_END + 1, 4096, |_| b'a'), Err(Errno::Efault));
    }

    #[test]
    fn scan_walks_off_user_end_before_nul_is_efault() {
        // A non-terminated path that reaches USER_VA_END mid-walk faults
        // rather than returning a partial string.
        let base = USER_VA_END - 4;
        assert_eq!(scan_user_cstr(base, 4096, |_| b'a'), Err(Errno::Efault));
    }
}
