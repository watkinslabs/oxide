//! Shared (return-value, errno) result the host oracle and the oxide
//! work-fn side both normalize into, so one comparator serves every family.

/// One syscall result, host or oxide side. `errno` is 0 on success (Linux
/// convention: only a `-1`-class return carries an errno).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outcome {
    pub ret: i64,
    pub errno: i32,
}

impl Outcome {
    pub const fn ok(ret: i64) -> Self { Outcome { ret, errno: 0 } }
    pub const fn err(errno: i32) -> Self { Outcome { ret: -1, errno } }

    /// Decode an oxide syscall-ABI return: `rv < 0` is `-errno` (`docs/15`
    /// negative-errno convention), else the raw success value.
    pub fn from_oxide_rv(rv: i64) -> Self {
        if rv < 0 { Outcome::err((-rv) as i32) } else { Outcome::ok(rv) }
    }

    /// Decode a host libc call: `-1` means consult `errno`, matching every
    /// libc wrapper `oracle.rs` uses.
    pub fn from_host(ret: i64) -> Self {
        // SAFETY: __errno_location() returns the calling thread's own valid errno cell.
        if ret == -1 { Outcome::err(unsafe { *libc::__errno_location() }) } else { Outcome::ok(ret) }
    }

    pub fn is_success(&self) -> bool { self.errno == 0 }

    /// Same success/failure class, and — on failure — the same errno. Success
    /// `ret` values are NOT compared here (fd numbers, inode-adjacent
    /// counters etc. never line up across two independent kernels); callers
    /// that care about a specific returned value fold it into their own
    /// case-local comparison before calling into `corpus`.
    pub fn same_errno_class(&self, other: &Outcome) -> bool {
        self.is_success() == other.is_success()
            && (!self.is_success() || self.errno == other.errno)
    }
}

/// Linux errno names for readable divergence reports. Not exhaustive —
/// falls back to the bare number. Extend as new families need new codes.
pub fn errno_name(e: i32) -> &'static str {
    match e {
        0 => "0",
        libc::EPERM => "EPERM", libc::ENOENT => "ENOENT", libc::ESRCH => "ESRCH",
        libc::EINTR => "EINTR", libc::EIO => "EIO", libc::ENXIO => "ENXIO",
        libc::EBADF => "EBADF", libc::EAGAIN => "EAGAIN", libc::ENOMEM => "ENOMEM",
        libc::EACCES => "EACCES", libc::EFAULT => "EFAULT", libc::EEXIST => "EEXIST",
        libc::EXDEV => "EXDEV", libc::ENODEV => "ENODEV", libc::ENOTDIR => "ENOTDIR",
        libc::EISDIR => "EISDIR", libc::EINVAL => "EINVAL", libc::ENFILE => "ENFILE",
        libc::EMFILE => "EMFILE", libc::ENOTTY => "ENOTTY", libc::EFBIG => "EFBIG",
        libc::ENOSPC => "ENOSPC", libc::ESPIPE => "ESPIPE", libc::EROFS => "EROFS",
        libc::EMLINK => "EMLINK", libc::EPIPE => "EPIPE", libc::ENAMETOOLONG => "ENAMETOOLONG",
        libc::ENOTEMPTY => "ENOTEMPTY", libc::ELOOP => "ELOOP", libc::ENOSYS => "ENOSYS",
        libc::EBUSY => "EBUSY", libc::EOPNOTSUPP => "EOPNOTSUPP",
        _ => "<other>",
    }
}

impl core::fmt::Display for Outcome {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.is_success() { write!(f, "Ok(ret={})", self.ret) }
        else { write!(f, "Err({}={})", errno_name(self.errno), self.errno) }
    }
}
