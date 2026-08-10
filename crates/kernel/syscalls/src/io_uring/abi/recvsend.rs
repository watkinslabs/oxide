// The per-operation flag word of the send and receive family, and the two
// behaviours it asks for that are not a plain transfer.
//
// `ioprio` is not a priority on these opcodes: it is their own flag half. Two
// of its bits change WHEN and HOW MANY TIMES the operation runs, so neither
// can be answered by the transfer alone:
//
//   * poll-first — the caller has already decided the description is not
//     ready and does not want an attempt that would block. The request is put
//     on the description's readiness FIRST and attempted only once it fires.
//   * multishot — one submission that stays armed, posting one completion per
//     delivery, each carrying the provided buffer it landed in and the
//     "more follows" flag, until something ends it. The completion that ends
//     it carries no "more" flag and reports WHY it stopped.
//
// Everything here is decision only — which bits an opcode defines, which of
// them are legal together, and what one pass of a multishot receive does
// next. The engine files that act on it are kernel-gated, so the decisions
// live here where `cargo test` can reach them (CLAUDE.md phantom-test rule).

use syscall::errno::Errno;

use super::bundle::IORING_RECVSEND_BUNDLE;
use super::ops::{IORING_OP_RECV, IORING_OP_RECVMSG, IORING_OP_SEND, IORING_OP_SENDMSG,
                 IORING_RECVSEND_POLL_FIRST, IORING_RECV_MULTISHOT, IOSQE_BUFFER_SELECT};

/// `IORING_RECVSEND_POLL_FIRST`, in the width the entry carries it.
pub const POLL_FIRST: u16 = IORING_RECVSEND_POLL_FIRST as u16;
/// `IORING_RECV_MULTISHOT`, in the width the entry carries it.
pub const MULTISHOT: u16 = IORING_RECV_MULTISHOT as u16;
/// `IORING_RECVSEND_FIXED_BUF` — the transfer runs through a registered
/// buffer named by `buf_index`. Refused: a registered buffer is a pinned
/// scatter list, and this family has no path that walks one.
pub const FIXED_BUF: u16 = 1 << 2;
/// `IORING_SEND_ZC_REPORT_USAGE` — a zero-copy send reports whether it copied.
/// It belongs to the zero-copy send opcodes, which are not dispatched, so it
/// is a bit of a different opcode's flag word here.
pub const SEND_ZC_REPORT_USAGE: u16 = 1 << 3;
/// `IORING_SEND_VECTORIZED` — `addr` points at a segment vector rather than
/// at the payload. Refused: the entry's buffer is read as one range.
pub const SEND_VECTORIZED: u16 = 1 << 5;

/// The bits the send family accepts. Everything outside it is `EINVAL` —
/// including the bits above that name a behaviour this kernel does not
/// perform, because an accepted flag that changes nothing is a downgrade the
/// caller cannot see.
pub const SEND_FLAGS: u16 = POLL_FIRST | IORING_RECVSEND_BUNDLE;
/// The bits the receive family accepts.
pub const RECV_FLAGS: u16 = POLL_FIRST | MULTISHOT | IORING_RECVSEND_BUNDLE;

/// `MSG_WAITALL` — wait for the whole buffer. Meaningless under multishot,
/// which reports each delivery as it lands.
const MSG_WAITALL: u32 = 0x100;

/// `MSG_DONTWAIT` — one attempt, no sleeping. Forced on every pass of a
/// multishot receive: the pass that finds nothing arms the description
/// instead of holding a worker asleep on it.
pub const MSG_DONTWAIT: u32 = 0x40;

/// Most passes one multishot receive makes before it goes back on the queue,
/// so a socket delivering without pause cannot hold a worker indefinitely.
pub const MULTISHOT_MAX_RETRY: u32 = 32;

/// Whether this opcode reads `ioprio` as its own flag word. # C: O(1)
pub fn reads_ioprio(op: u8) -> bool {
    matches!(op, IORING_OP_SEND | IORING_OP_SENDMSG | IORING_OP_RECV | IORING_OP_RECVMSG)
}

/// The bits `op` accepts there. # C: O(1)
pub fn valid_flags(op: u8) -> u16 {
    match op {
        IORING_OP_SEND | IORING_OP_SENDMSG => SEND_FLAGS,
        IORING_OP_RECV | IORING_OP_RECVMSG => RECV_FLAGS,
        _ => 0,
    }
}

/// The flag word's admission ladder.
///
/// | rung | errno |
/// |---|---|
/// | a bit the opcode's family does not define | `EINVAL` |
/// | a bundle on a message-carrying opcode | `EINVAL` |
/// | multishot without a provided-buffer group | `EINVAL` |
/// | multishot with `MSG_WAITALL` | `EINVAL` |
/// | multishot on a message-carrying receive | `EINVAL` |
///
/// Multishot needs a group because it has no other buffer to deliver into:
/// the entry's own buffer is one buffer, and the second delivery would
/// overwrite the first. `MSG_WAITALL` asks for one full buffer and multishot
/// reports each delivery as it lands, so the two describe different
/// completions for the same bytes. # C: O(1)
pub fn admit(op: u8, sqe_flags: u8, ioprio: u16, msg_flags: u32) -> Result<(), Errno> {
    if !reads_ioprio(op) { return Ok(()); }
    if ioprio & !valid_flags(op) != 0 { return Err(Errno::Einval); }
    super::bundle::admit(op, ioprio)?;
    if ioprio & MULTISHOT == 0 { return Ok(()); }
    if sqe_flags & IOSQE_BUFFER_SELECT == 0 { return Err(Errno::Einval); }
    if msg_flags & MSG_WAITALL != 0 { return Err(Errno::Einval); }
    if op == IORING_OP_RECVMSG { return Err(Errno::Einval); }
    Ok(())
}

/// Whether the entry asked to be armed on its description before any transfer
/// is attempted. # C: O(1)
pub fn poll_first(op: u8, ioprio: u16) -> bool {
    reads_ioprio(op) && ioprio & POLL_FIRST != 0
}

/// Whether the entry is a multishot receive. Admission has already refused
/// every other shape the bit can appear in, so the group is present by the
/// time this answers true. # C: O(1)
pub fn multishot(op: u8, sqe_flags: u8, ioprio: u16) -> bool {
    op == IORING_OP_RECV
        && ioprio & MULTISHOT != 0
        && sqe_flags & IOSQE_BUFFER_SELECT != 0
}

/// Whether the entry must not be attempted in the submitting task.
///
/// Both behaviours outlive their submission — one waits for readiness before
/// it starts, the other posts completions long after — so both need the
/// request object that only a deferred entry gets. An attempt inline would
/// report the first pass as the whole answer. # C: O(1)
pub fn defers_before_issue(op: u8, sqe_flags: u8, ioprio: u16) -> bool {
    poll_first(op, ioprio) || multishot(op, sqe_flags, ioprio)
}

/// What one pass of a multishot receive does next.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Step {
    /// Report the delivery with "more follows" and take another pass.
    More,
    /// Report the delivery with "more follows" and go back on the queue: this
    /// request has had its run of passes and another may be waiting.
    Yield,
    /// Nothing to deliver. Arm the description; no completion is posted, and
    /// the request stays live.
    Wait,
    /// Stop. This result is the final completion, and it carries no
    /// "more follows" flag — which is how the caller learns the submission is
    /// no longer armed and why.
    Done(i64),
}

/// # C: O(1)
fn eagain() -> i64 { -(Errno::Eagain.as_i32() as i64) }

/// Decide one pass of a multishot receive from what the transfer returned and
/// how many passes this run has already made.
///
/// A zero-length delivery ends it: the peer is finished, and a request left
/// armed on a description that reports readiness forever would spin. A
/// failure ends it too, and its errno is the terminal completion — including
/// the one the group runs dry with, which is the ordinary way a multishot
/// receive stops. # C: O(1)
pub fn step(res: i64, passes: u32) -> Step {
    if res == eagain() { return Step::Wait; }
    if res <= 0 { return Step::Done(res); }
    if passes + 1 >= MULTISHOT_MAX_RETRY { return Step::Yield; }
    Step::More
}

/// The message flags one pass of a multishot receive runs with. # C: O(1)
pub fn pass_msg_flags(msg_flags: u32) -> u32 { msg_flags | MSG_DONTWAIT }

#[cfg(test)]
#[path = "recvsend/tests.rs"]
mod tests;
