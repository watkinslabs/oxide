use core::sync::atomic::{AtomicI32, Ordering};

/// Canonical Linux-style `sk_err`, shared by socket and transport owner.
pub struct SocketError {
    errno: AtomicI32,
}

impl SocketError {
    /// Empty socket error state. # C: O(1)
    pub const fn new() -> Self { Self { errno: AtomicI32::new(0) } }

    /// Publish the latest positive Linux errno. # C: O(1)
    pub fn set(&self, errno: i32) -> bool {
        if errno <= 0 { return false; }
        self.errno.store(errno, Ordering::Release);
        true
    }

    /// Read and clear the pending errno. # C: O(1)
    pub fn take(&self) -> i32 { self.errno.swap(0, Ordering::AcqRel) }

    /// Observe pending error state without consuming it. # C: O(1)
    pub fn has(&self) -> bool { self.errno.load(Ordering::Acquire) != 0 }
}

impl Default for SocketError { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::SocketError;
    use syscall::errno::Errno;

    #[test]
    fn latest_positive_error_is_canonical() {
        let error = SocketError::new();
        assert!(!error.set(0));
        assert!(!error.set(-1));
        assert!(error.set(Errno::Econnrefused as i32));
        assert!(error.set(Errno::Econnreset as i32));
        assert_eq!(error.take(), Errno::Econnreset as i32);
        assert_eq!(error.take(), 0);
    }
}
