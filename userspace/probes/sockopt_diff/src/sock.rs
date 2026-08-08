//! Socket + sockopt plumbing shared by the `netlink` and `sockopt` probe
//! modules: opening the `AF_NETLINK`/`NETLINK_ROUTE` fd under test, raw
//! `setsockopt`/`getsockopt` wrappers that report `(rc, errno)`, and the
//! privilege-ladder fork helper.

use crate::record::errno;
use std::os::raw::c_void;

/// Sentinel byte pattern for get-buffers: any of these left un-overwritten by
/// the kernel is directly visible in the recorded hex, which is how the
/// `NETLINK_LIST_MEMBERSHIPS` word-vs-byte probe proves what the kernel did
/// and did not touch.
pub const SENTINEL: u8 = 0x5a;

/// Open an `AF_NETLINK`/`NETLINK_ROUTE` socket, unbound. Membership and the
/// `SOL_NETLINK` options under test do not require a prior `bind(2)`. # C: O(1)
pub fn netlink_fd() -> i32 {
    // SAFETY: socket(2) with fixed, valid arguments; no user pointers.
    unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE) }
}

/// `setsockopt(fd, level, name, optval, optlen)` -> `(rc, errno)`.
/// `optlen` is a raw `u32` so callers can construct the "negative optlen"
/// probe by transmuting a negative `i32` through it. # C: O(1)
pub fn setopt_raw(fd: i32, level: i32, name: i32, optval: *const c_void, optlen: u32) -> (i64, i32) {
    // SAFETY: optval is either NULL (the NULL-optval probe) or points at a
    // live local the caller owns for the duration of this call; optlen is
    // exactly the byte length the caller intends the kernel to read/reject.
    let rc = unsafe { libc::setsockopt(fd, level, name, optval, optlen) };
    (rc as i64, if rc < 0 { errno() } else { 0 })
}

/// `getsockopt(fd, level, name, optval, &mut optlen)` -> `(rc, errno, optlen_after)`.
/// `optlen` is a raw `u32` so callers can pass a deliberately negative value
/// through the same transmute the set-side probe uses. # C: O(1)
pub fn getopt_raw(fd: i32, level: i32, name: i32, optval: *mut c_void, optlen: u32) -> (i64, i32, u32) {
    let mut len = optlen;
    // SAFETY: optval is either NULL (the NULL-optval probe) or points at a
    // live local buffer of at least `optlen` bytes the caller owns; len is a
    // valid local the kernel may rewrite in place.
    let rc = unsafe { libc::getsockopt(fd, level, name, optval, &mut len as *mut u32) };
    (rc as i64, if rc < 0 { errno() } else { 0 }, len)
}

/// Set then get a 4-byte `int` option, returning
/// `(set_rc, set_errno, get_rc, get_errno, get_len, get_value)`. # C: O(1)
pub fn scalar_set_get(fd: i32, level: i32, name: i32, set_val: i32) -> (i64, i32, i64, i32, u32, i32) {
    let (src, se) = setopt_raw(fd, level, name,
        &set_val as *const i32 as *const c_void, 4);
    let mut got: i32 = SENTINEL as i32 * 0x0101_0101u32 as i32;
    let (grc, ge, glen) = getopt_raw(fd, level, name, &mut got as *mut i32 as *mut c_void, 4);
    (src, se, grc, ge, glen, got)
}

/// Get-only 4-byte `int` read, returning `(rc, errno, len, value)`. # C: O(1)
pub fn scalar_get(fd: i32, level: i32, name: i32) -> (i64, i32, u32, i32) {
    let mut got: i32 = SENTINEL as i32 * 0x0101_0101u32 as i32;
    let (rc, err, len) = getopt_raw(fd, level, name, &mut got as *mut i32 as *mut c_void, 4);
    (rc, err, len, got)
}

/// Run `f("root")` in this process, then `f("dropped")` in a forked child
/// whose uid/gid have been lowered to `uapi::UNPRIV_ID` — which the standard
/// setuid-fixup rule clears CAP_NET_ADMIN/CAP_NET_RAW/CAP_NET_BROADCAST from,
/// since the process started at uid 0 with the full permitted set and
/// `PR_SET_KEEPCAPS` is never set here.
///
/// `f` must reach every record line through `record::out`/`result`, which
/// write with one unbuffered `write(2)` each — required so a mid-buffer
/// `fork()` cannot duplicate a parent's unflushed line into the child's
/// output (`CLAUDE.md` boot-corruption class 12 is the same fork+buffering
/// hazard in the kernel's own probes). # C: O(f)
pub fn priv_pair(f: impl Fn(&str)) {
    f("root");
    // SAFETY: fork() duplicates this single-threaded process; the child only
    // calls setresgid/setresuid/f/_exit before either exiting or (on error)
    // falling through to _exit, never returning into caller state shared
    // with the parent.
    match unsafe { libc::fork() } {
        0 => {
            // SAFETY: gid must drop before uid — dropping uid first would
            // remove the privilege needed to change gid afterward.
            unsafe { libc::setresgid(crate::uapi::UNPRIV_ID as libc::gid_t, crate::uapi::UNPRIV_ID as libc::gid_t, crate::uapi::UNPRIV_ID as libc::gid_t); }
            // SAFETY: drops real/effective/saved uid to the unprivileged
            // sentinel id, clearing the process's capability sets per the
            // kernel's setuid-fixup rule.
            unsafe { libc::setresuid(crate::uapi::UNPRIV_ID, crate::uapi::UNPRIV_ID, crate::uapi::UNPRIV_ID); }
            f("dropped");
            // SAFETY: _exit terminates the child without touching any
            // parent-shared buffered state (there is none: record::out
            // never buffers).
            unsafe { libc::_exit(0); }
        }
        pid if pid > 0 => {
            let mut status: i32 = 0;
            // SAFETY: waits on the exact child pid just forked, with a valid
            // local status pointer.
            unsafe { libc::waitpid(pid, &mut status as *mut i32, 0); }
        }
        _ => crate::record::result("priv", "fork", -1, errno()),
    }
}
