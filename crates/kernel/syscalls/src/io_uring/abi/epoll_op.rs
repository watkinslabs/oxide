// `IORING_OP_EPOLL_CTL` and `IORING_OP_EPOLL_WAIT` — driving an epoll set from
// a ring.
//
// The two are opposite halves of the same set. The control entry names the
// operation in `len` and the watched descriptor in `off`, because its own `fd`
// is already spent naming the epoll set. The wait entry names only where the
// events go and how many fit; it takes no timeout at all, and that absence is
// the design: a wait that found nothing does not sleep, it reports `EAGAIN`
// and the ring arms it on the set's own readiness, so one submission costs no
// thread while it waits.
//
// Ungated: the field ladder is a decision, and the file that reaches the epoll
// set is kernel-gated (CLAUDE.md phantom-test rule).

use syscall::errno::Errno;

use crate::io_uring_sqe::Sqe;

/// One harvest from an epoll set, decoded.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EpollWaitOp {
    /// Where the `struct epoll_event` array goes.
    pub events: u64,
    /// How many entries fit there.
    pub maxevents: u32,
}

/// Admit a control entry.
///
/// | rung | errno |
/// |---|---|
/// | `buf_index` or `splice_fd_in` non-zero | `EINVAL` |
///
/// Both are fields this operation does not read. Accepting a value in one
/// would make it unusable the day it acquires a meaning. # C: O(1)
pub fn prep_ctl(sqe: &Sqe) -> Result<(), Errno> {
    if sqe.buf_index != 0 || sqe.splice_fd_in != 0 { return Err(Errno::Einval); }
    Ok(())
}

/// Admit and decode a wait entry.
///
/// | rung | errno |
/// |---|---|
/// | `off`, the reserved flag word, `buf_index` or `splice_fd_in` non-zero | `EINVAL` |
///
/// `off` is refused rather than read as a timeout: this operation has none,
/// and a caller that supplied one would otherwise be given an immediate
/// harvest while believing it had asked to wait. # C: O(1)
pub fn prep_wait(sqe: &Sqe) -> Result<EpollWaitOp, Errno> {
    if sqe.off != 0 || sqe.op_flags != 0 || sqe.buf_index != 0 || sqe.splice_fd_in != 0 {
        return Err(Errno::Einval);
    }
    Ok(EpollWaitOp { events: sqe.addr, maxevents: sqe.len })
}

/// What one harvest reports.
///
/// A harvest that found nothing is not an empty answer — it is "not yet". The
/// ring turns it into an arming on the set's readiness, and the submitter
/// hears nothing until events actually exist. Reporting `0` instead would end
/// the submission with a completion that told the caller nothing and cost it a
/// resubmission per idle poll. # C: O(1)
pub fn wait_result(harvested: i64) -> i64 {
    if harvested == 0 { return -(Errno::Eagain.as_i32() as i64); }
    harvested
}

#[cfg(test)]
#[path = "epoll_op/tests.rs"]
mod tests;
