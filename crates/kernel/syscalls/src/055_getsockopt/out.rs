use syscall::errno::Errno;

/// The `(optval, optlen)` copyout pair one `getsockopt` answers through.
/// Every writer reads the caller's length FIRST, truncates the value to it,
/// then publishes the length actually written — Linux's `lenout` shape.
pub(super) struct OptOut { pub optval: u64, pub optlen_p: u64 }

impl OptOut {
    /// # C: O(1)
    pub fn new(optval: u64, optlen_p: u64) -> Self { Self { optval, optlen_p } }

    /// Publish an `int`-shaped option value. # C: O(1)
    pub fn i32(&self, val: i32) -> i64 { self.bytes(&val.to_ne_bytes()) }

    /// The caller's declared buffer length, screened once for the readers that
    /// branch on it before they choose a value. # C: O(1)
    pub fn requested_len(&self) -> Result<usize, i64> {
        let mut raw_len = [0u8; 4];
        if uaccess::copy_from_user(&mut raw_len, self.optlen_p).is_err() {
            return Err(-(Errno::Efault.as_i32() as i64));
        }
        let requested = i32::from_ne_bytes(raw_len);
        if requested < 0 { return Err(-(Errno::Einval.as_i32() as i64)); }
        Ok(requested as usize)
    }

    /// Publish a value whose length the caller already had to supply exactly,
    /// leaving the length word untouched. # C: O(n)
    pub fn value_only(&self, value: &[u8]) -> i64 {
        if !value.is_empty() && uaccess::copy_to_user(self.optval, value).is_err() {
            return -(Errno::Efault.as_i32() as i64);
        }
        0
    }

    /// Publish a value whose length the option table already resolved: the
    /// bytes go out as they are, and the published length is exactly how many
    /// were written. # C: O(n)
    pub fn exact(&self, value: &[u8]) -> i64 {
        if !value.is_empty() && uaccess::copy_to_user(self.optval, value).is_err() {
            return -(Errno::Efault.as_i32() as i64);
        }
        if uaccess::copy_to_user(self.optlen_p, &(value.len() as u32).to_ne_bytes()).is_err() {
            return -(Errno::Efault.as_i32() as i64);
        }
        0
    }

    /// Publish only a length — the size a value needs when the caller's buffer
    /// was too small to receive it. # C: O(1)
    pub fn length_only(&self, len: usize) -> i64 {
        if uaccess::copy_to_user(self.optlen_p, &(len as u32).to_ne_bytes()).is_err() {
            return -(Errno::Efault.as_i32() as i64);
        }
        0
    }

    /// Publish a byte-shaped option value truncated to the caller's length.
    /// # C: O(n)
    pub fn bytes(&self, value: &[u8]) -> i64 {
        let mut raw_len = [0u8; 4];
        if uaccess::copy_from_user(&mut raw_len, self.optlen_p).is_err() {
            return -(Errno::Efault.as_i32() as i64);
        }
        let requested = i32::from_ne_bytes(raw_len);
        if requested < 0 { return -(Errno::Einval.as_i32() as i64); }
        let take = core::cmp::min(requested as usize, value.len());
        if take != 0 && uaccess::copy_to_user(self.optval, &value[..take]).is_err() {
            return -(Errno::Efault.as_i32() as i64);
        }
        if uaccess::copy_to_user(self.optlen_p, &(take as u32).to_ne_bytes()).is_err() {
            return -(Errno::Efault.as_i32() as i64);
        }
        0
    }
}
