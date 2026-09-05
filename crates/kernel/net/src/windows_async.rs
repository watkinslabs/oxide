//! Windows overlapped socket completion over the Linux socket owner.
//!
//! The operation owns only its completion record. Readiness and socket errors
//! remain in `InetSocket`/`SocketError`; an adapter supplies those observations
//! when it completes this record.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// NT status values used by asynchronous Winsock completion.
pub mod status {
    pub const SUCCESS: u32 = 0;
    pub const PENDING: u32 = 0x0000_0103;
    pub const BUFFER_OVERFLOW: u32 = 0x8000_0005;
    pub const CANCELLED: u32 = 0xc000_0120;
    pub const IO_TIMEOUT: u32 = 0xc000_00b5;
    pub const CONNECTION_DISCONNECTED: u32 = 0xc000_020c;
    pub const CONNECTION_RESET: u32 = 0xc000_020d;
    pub const CONNECTION_REFUSED: u32 = 0xc000_0236;
    pub const NETWORK_UNREACHABLE: u32 = 0xc000_023c;
    pub const HOST_UNREACHABLE: u32 = 0xc000_023d;
    pub const CONNECTION_ABORTED: u32 = 0xc000_0241;
}

/// Winsock errors returned by the overlapped-result adapter.
pub mod error {
    pub const IO_INCOMPLETE: u32 = 996;
    pub const OPERATION_ABORTED: u32 = 995;
    pub const EFAULT: u32 = 10014;
    pub const EMSGSIZE: u32 = 10040;
    pub const ENOBUFS: u32 = 10055;
    pub const ENETUNREACH: u32 = 10051;
    pub const EHOSTUNREACH: u32 = 10065;
    pub const ETIMEDOUT: u32 = 10060;
    pub const ECONNRESET: u32 = 10054;
    pub const ECONNREFUSED: u32 = 10061;
    pub const ECONNABORTED: u32 = 10053;
    pub const EINVAL: u32 = 10022;
}

/// The observable result of one completed overlapped operation.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Completion {
    pub status: u32,
    pub bytes: u64,
    pub flags: u32,
}

/// One 64-bit `OVERLAPPED` completion record.
pub struct Overlapped {
    /// Status is published last, pairing with the acquire load in `result`.
    status: AtomicU32,
    claimed: core::sync::atomic::AtomicBool,
    information: AtomicU64,
    flags: AtomicU32,
}

impl Overlapped {
    /// Allocate a record in the pending state used at async submission. # C: O(1)
    pub const fn new() -> Self {
        Self { status: AtomicU32::new(status::PENDING),
            claimed: core::sync::atomic::AtomicBool::new(false), information: AtomicU64::new(0),
            flags: AtomicU32::new(0) }
    }

    /// Re-arm only a terminal record; a live operation cannot be overwritten. # C: O(1)
    pub fn begin(&self) -> bool {
        if self.status.load(Ordering::Acquire) == status::PENDING { return false; }
        self.claimed.store(false, Ordering::Release);
        self.status.store(status::PENDING, Ordering::Release);
        true
    }

    /// Publish bytes and flags before the terminal status. Exactly one producer wins. # C: O(1)
    pub fn complete(&self, status: u32, bytes: u64, flags: u32) -> bool {
        if status == status::PENDING { return false; }
        if self.status.load(Ordering::Acquire) != status::PENDING
            || self.claimed.compare_exchange(false, true, Ordering::AcqRel,
                Ordering::Acquire).is_err() { return false; }
        self.information.store(bytes, Ordering::Relaxed);
        self.flags.store(flags, Ordering::Relaxed);
        self.status.store(status, Ordering::Release);
        true
    }

    /// Cancel a pending operation and retain the same terminal publication rules. # C: O(1)
    pub fn cancel(&self) -> bool { self.complete(status::CANCELLED, 0, 0) }

    /// Read the status with acquire ordering, then return the completed payload. # C: O(1)
    pub fn result(&self) -> Result<Completion, u32> {
        let current = self.status.load(Ordering::Acquire);
        if current == status::PENDING { return Err(error::IO_INCOMPLETE); }
        Ok(Completion { status: current, bytes: self.information.load(Ordering::Relaxed),
            flags: self.flags.load(Ordering::Relaxed) })
    }

    /// Return the native status for an adapter that needs to wait on readiness. # C: O(1)
    pub fn is_complete(&self) -> bool { self.status.load(Ordering::Acquire) != status::PENDING }
}

/// Translate a terminal NT status to the Winsock result namespace. # C: O(1)
pub const fn status_error(value: u32) -> u32 {
    match value {
        status::SUCCESS => 0,
        status::CANCELLED => error::OPERATION_ABORTED,
        status::BUFFER_OVERFLOW => error::EMSGSIZE,
        status::IO_TIMEOUT => error::ETIMEDOUT,
        status::CONNECTION_DISCONNECTED | status::CONNECTION_RESET => error::ECONNRESET,
        status::CONNECTION_REFUSED => error::ECONNREFUSED,
        status::NETWORK_UNREACHABLE => error::ENETUNREACH,
        status::HOST_UNREACHABLE => error::EHOSTUNREACH,
        status::CONNECTION_ABORTED => error::ECONNABORTED,
        _ if value & 0x8000_0000 == 0 => 0,
        _ => error::EINVAL,
    }
}

/// Map a canonical positive Linux socket errno to its Winsock completion error. # C: O(1)
pub const fn errno_error(errno: i32) -> u32 {
    use syscall::errno::Errno;
    match errno {
        x if x == Errno::Emsgsize as i32 => error::EMSGSIZE,
        x if x == Errno::Enobufs as i32 => error::ENOBUFS,
        x if x == Errno::Enetunreach as i32 => error::ENETUNREACH,
        x if x == Errno::Ehostunreach as i32 => error::EHOSTUNREACH,
        x if x == Errno::Etimedout as i32 => error::ETIMEDOUT,
        x if x == Errno::Econnreset as i32 => error::ECONNRESET,
        x if x == Errno::Econnrefused as i32 => error::ECONNREFUSED,
        x if x == Errno::Econnaborted as i32 => error::ECONNABORTED,
        x if x == Errno::Eacces as i32 => 10013,
        _ => error::EINVAL,
    }
}

#[cfg(test)]
mod tests {
    use super::{error, errno_error, status, status_error, Overlapped};
    use syscall::errno::Errno;

    #[test]
    fn pending_is_incomplete_until_terminal_publication() {
        let op = Overlapped::new();
        assert_eq!(op.result(), Err(error::IO_INCOMPLETE));
        assert!(!op.is_complete());
        assert!(op.complete(status::SUCCESS, 37, 9));
        assert_eq!(op.result().unwrap().bytes, 37);
        assert_eq!(op.result().unwrap().flags, 9);
    }

    #[test]
    fn duplicate_completion_and_pending_status_are_rejected() {
        let op = Overlapped::new();
        assert!(!op.complete(status::PENDING, 1, 0));
        assert!(op.complete(status::SUCCESS, 1, 0));
        assert!(!op.complete(status::CONNECTION_RESET, 2, 0));
    }

    #[test]
    fn cancellation_is_terminal_and_rearm_is_explicit() {
        let op = Overlapped::new();
        assert!(op.cancel());
        assert_eq!(op.result().unwrap().status, status::CANCELLED);
        assert_eq!(status_error(status::CANCELLED), error::OPERATION_ABORTED);
        assert!(op.begin());
        assert_eq!(op.result(), Err(error::IO_INCOMPLETE));
        assert!(!op.begin());
    }

    #[test]
    fn status_and_linux_errno_errors_share_winsock_values() {
        assert_eq!(status_error(status::CONNECTION_REFUSED), error::ECONNREFUSED);
        assert_eq!(status_error(status::NETWORK_UNREACHABLE), error::ENETUNREACH);
        assert_eq!(errno_error(Errno::Econnreset as i32), error::ECONNRESET);
        assert_eq!(errno_error(Errno::Ehostunreach as i32), error::EHOSTUNREACH);
    }

    #[test]
    fn unknown_failure_does_not_look_like_success() {
        assert_ne!(status_error(0xc000_0001), 0);
        assert_ne!(errno_error(Errno::Eio as i32), 0);
    }
}
