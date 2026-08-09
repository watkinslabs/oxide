// `sys_waitid`'s `siginfo_t` copy-out, as bytes. The layout and the
// which-fields-are-set decision are pure and live here; the gated slot only
// validates the user range and copies the buffer.

use super::{siginfo_from_event, WaitEventKind};

/// `sizeof(siginfo_t)` — the whole structure is written, zeroed remainder
/// included, so no stale user bytes survive under the union's tail.
pub const SIGINFO_BYTES: usize = 128;

pub const SIGINFO_OFF_SIGNO:  usize = 0;
pub const SIGINFO_OFF_ERRNO:  usize = 4;
pub const SIGINFO_OFF_CODE:   usize = 8;
pub const SIGINFO_OFF_PID:    usize = 16;
pub const SIGINFO_OFF_UID:    usize = 20;
pub const SIGINFO_OFF_STATUS: usize = 24;

/// The reported event, as the siginfo encoder needs it.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct WaitReport {
    pub kind:  WaitEventKind,
    /// Wait-encoded status, decoded here into `si_code`/`si_status`.
    pub wstat: i32,
    /// The child's VPID in the waiter's pid namespace.
    pub pid:   i32,
    pub uid:   u32,
}

/// Build the `siginfo_t` image `waitid` copies out. `signo` is `SIGCHLD`.
///
/// `None` — a `WNOHANG` miss, or an error return — leaves the whole structure
/// zero, `si_signo` included: that zero is how userspace tells "nothing
/// happened" apart from a real report. The buffer is still written in that
/// case, matching the copy-out that runs on every non-null `infop` regardless
/// of the return value.
/// # C: O(1)
pub fn siginfo_bytes(signo: i32, report: Option<WaitReport>) -> [u8; SIGINFO_BYTES] {
    let mut b = [0u8; SIGINFO_BYTES];
    let Some(r) = report else { return b };
    let (si_code, si_status) = siginfo_from_event(r.kind, r.wstat);
    put_i32(&mut b, SIGINFO_OFF_SIGNO,  signo);
    put_i32(&mut b, SIGINFO_OFF_ERRNO,  0);
    put_i32(&mut b, SIGINFO_OFF_CODE,   si_code);
    put_i32(&mut b, SIGINFO_OFF_PID,    r.pid);
    put_i32(&mut b, SIGINFO_OFF_UID,    r.uid as i32);
    put_i32(&mut b, SIGINFO_OFF_STATUS, si_status);
    b
}

/// # C: O(1)
fn put_i32(b: &mut [u8; SIGINFO_BYTES], off: usize, v: i32) {
    b[off..off + 4].copy_from_slice(&v.to_ne_bytes());
}

/// Read one field back out of a `siginfo_t` image. # C: O(1)
pub fn siginfo_field(b: &[u8; SIGINFO_BYTES], off: usize) -> i32 {
    let mut w = [0u8; 4];
    w.copy_from_slice(&b[off..off + 4]);
    i32::from_ne_bytes(w)
}

#[cfg(test)]
#[path = "siginfo_tests.rs"]
mod tests;
