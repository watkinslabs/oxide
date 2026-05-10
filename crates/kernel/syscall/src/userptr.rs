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
