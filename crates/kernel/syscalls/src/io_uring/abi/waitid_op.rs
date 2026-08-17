// `IORING_OP_WAITID` — waiting for a child's state change as a submission
// entry.
//
// The operation names no file, so its `fd` carries the id being waited on and
// the id TYPE goes in `len`. The options word lands in `file_index` — the same
// slot a descriptor-creating entry uses to ask for a direct descriptor, which
// this operation never does. Reading either from the field its name suggests
// would swap two small integers that are both plausible, and the resulting
// wait would report the wrong child.
//
// No rusage: the entry has nowhere to put one, so the wait is prepared without
// it rather than with a pointer taken from a field meaning something else.
//
// Ungated: the field ladder is a decision, and the file that parks on the
// child is kernel-gated (CLAUDE.md phantom-test rule).

use syscall::errno::Errno;

use crate::io_uring_sqe::Sqe;

/// One child wait, decoded.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct WaitidOp {
    /// `idtype` — which kind of id `id` is.
    pub which: u32,
    /// The id itself.
    pub id: i32,
    /// The `WEXITED`/`WSTOPPED`/… options word.
    pub options: u32,
    /// Where the `siginfo_t` goes, or 0 for "do not report one".
    pub infop: u64,
}

/// Admit and decode a wait entry.
///
/// | rung | errno |
/// |---|---|
/// | `addr`, `buf_index`, `addr3` or the reserved flag word non-zero | `EINVAL` |
///
/// Every one of those is a field this operation does not read. The id ladder
/// itself — which id types exist, which option combinations are legal — is the
/// wait engine's, not the entry's, so it is not repeated here: a second copy
/// would be a second answer. # C: O(1)
pub fn prep(sqe: &Sqe) -> Result<WaitidOp, Errno> {
    if sqe.addr != 0 || sqe.buf_index != 0 || sqe.addr3 != 0 || sqe.op_flags != 0 {
        return Err(Errno::Einval);
    }
    Ok(WaitidOp {
        which: sqe.len,
        id: sqe.fd,
        options: sqe.file_index(),
        infop: sqe.off,
    })
}

#[cfg(test)]
#[path = "waitid_op/tests.rs"]
mod tests;
