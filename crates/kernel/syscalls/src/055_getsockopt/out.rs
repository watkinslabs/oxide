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
