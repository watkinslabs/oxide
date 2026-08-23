// The per-operation flag word of the send and receive family, and the
// behaviours it asks for that are not a plain transfer.
//
// `ioprio` is not a priority on these opcodes: it is their own flag half.
// Four of its bits change WHEN, HOW MANY TIMES, or THROUGH WHAT MEMORY the
// operation runs, so none can be answered by the transfer alone:
//
//   * poll-first — the caller has already decided the description is not
//     ready and does not want an attempt that would block. The request is put
//     on the description's readiness FIRST and attempted only once it fires.
//   * multishot — one submission that stays armed, posting one completion per
//     delivery, each carrying the provided buffer it landed in and the
//     "more follows" flag, until something ends it. The completion that ends
//     it carries no "more" flag and reports WHY it stopped.
//   * fixed buffer — the bytes move through the frames pinned at registration
//     time, named by index, never through an address the caller could have
//     remapped in between.
//   * vectorized send — `addr` names a segment vector rather than a payload,
//     so one submission sends a gathered message.
//
// Module manifest:
//   dest  — where a buffer-selecting receive puts the bytes, including the
//           frame a multishot `RECVMSG` lays out inside the drawn buffer.
//   fixed — the window a registered-buffer transfer occupies, and the
//           refusals a malformed one earns before any byte moves.
//   zc    — the zero-copy send's own flag word, and the second completion it
//           posts to say the payload memory is the caller's again.
//
// Everything here is decision only. The engine files that act on it are
// kernel-gated, so the decisions live here where `cargo test` can reach them
// (CLAUDE.md phantom-test rule).

use syscall::errno::Errno;

use super::bundle::IORING_RECVSEND_BUNDLE;
use super::ops::{IORING_OP_RECV, IORING_OP_RECVMSG, IORING_OP_SEND, IORING_OP_SENDMSG,
                 IORING_RECVSEND_FIXED_BUF, IORING_RECVSEND_POLL_FIRST, IORING_RECV_MULTISHOT,
                 IORING_SEND_VECTORIZED, IORING_SEND_ZC_REPORT_USAGE, IOSQE_BUFFER_SELECT};

#[path = "recvsend/dest.rs"]  pub mod dest;
#[path = "recvsend/fixed.rs"] pub mod fixed;
#[path = "recvsend/zc.rs"]    pub mod zc;

/// `IORING_RECVSEND_POLL_FIRST`, in the width the entry carries it.
pub const POLL_FIRST: u16 = IORING_RECVSEND_POLL_FIRST as u16;
/// `IORING_RECV_MULTISHOT`, in the width the entry carries it.
pub const MULTISHOT: u16 = IORING_RECV_MULTISHOT as u16;
/// `IORING_RECVSEND_FIXED_BUF`, in the width the entry carries it.
pub const FIXED_BUF: u16 = IORING_RECVSEND_FIXED_BUF as u16;
/// `IORING_SEND_ZC_REPORT_USAGE`, in the width the entry carries it. It is a
/// flag of the ZERO-COPY send opcodes, not of these: on a plain send the bit
/// names a notification completion this entry never posts, so it is outside
/// both masks below and refused.
pub const SEND_ZC_REPORT_USAGE: u16 = IORING_SEND_ZC_REPORT_USAGE as u16;
/// `IORING_SEND_VECTORIZED`, in the width the entry carries it.
pub const SEND_VECTORIZED: u16 = IORING_SEND_VECTORIZED as u16;

/// The bits the send family accepts. Everything outside it is `EINVAL` —
/// an accepted flag that changes nothing is a downgrade the caller cannot see.
pub const SEND_FLAGS: u16 = POLL_FIRST | IORING_RECVSEND_BUNDLE | SEND_VECTORIZED | FIXED_BUF;
/// The bits the receive family accepts.
pub const RECV_FLAGS: u16 = POLL_FIRST | MULTISHOT | IORING_RECVSEND_BUNDLE | FIXED_BUF;

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
/// | a fixed buffer on a message-carrying opcode | `EINVAL` |
/// | a fixed buffer together with a provided-buffer group | `EINVAL` |
/// | a fixed buffer with a bundle, a vector or multishot | `EINVAL` |
/// | multishot without a provided-buffer group | `EINVAL` |
/// | multishot with `MSG_WAITALL` | `EINVAL` |
/// | a bundle on a message-carrying opcode | `EINVAL` |
///
/// A registered buffer is ONE pinned window named by index. It cannot also be
/// drawn from a group (two answers to "where do the bytes go"), cannot span a
/// run of group buffers, cannot be re-delivered into per multishot pass, and
/// on the vectorized send the entry's `addr` names a vector rather than the
/// window — so every one of those pairings describes two different transfers.
///
/// Multishot needs a group because it has no other buffer to deliver into:
/// the entry's own buffer is one buffer, and the second delivery would
/// overwrite the first. `MSG_WAITALL` asks for one full buffer and multishot
/// reports each delivery as it lands, so the two describe different
/// completions for the same bytes. # C: O(1)
pub fn admit(op: u8, sqe_flags: u8, ioprio: u16, msg_flags: u32) -> Result<(), Errno> {
    if !reads_ioprio(op) { return Ok(()); }
    if ioprio & !valid_flags(op) != 0 { return Err(Errno::Einval); }
    if ioprio & FIXED_BUF != 0 { fixed::admit(op, sqe_flags, ioprio)?; }
    if ioprio & MULTISHOT != 0 {
        if sqe_flags & IOSQE_BUFFER_SELECT == 0 { return Err(Errno::Einval); }
        if msg_flags & MSG_WAITALL != 0 { return Err(Errno::Einval); }
    }
    super::bundle::admit(op, ioprio)
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
    matches!(op, IORING_OP_RECV | IORING_OP_RECVMSG)
        && ioprio & MULTISHOT != 0
        && sqe_flags & IOSQE_BUFFER_SELECT != 0
}

/// Whether the entry's transfer runs through a registered buffer. # C: O(1)
pub fn fixed_buf(op: u8, ioprio: u16) -> bool {
    matches!(op, IORING_OP_SEND | IORING_OP_RECV) && ioprio & FIXED_BUF != 0
}

/// Whether a plain send takes its payload from a segment vector at `addr`.
/// A message-carrying send always describes a vector, so the bit adds nothing
/// there and names no second behaviour. # C: O(1)
pub fn vectorized_send(op: u8, ioprio: u16) -> bool {
    op == IORING_OP_SEND && ioprio & SEND_VECTORIZED != 0
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

/// Whether a completion reports that the socket still holds data.
///
/// The count is what the socket would answer a queue-length query with, so
/// the flag and that query can never disagree. # C: O(1)
pub fn sock_nonempty(op: u8, inq: u64) -> u32 {
    if !matches!(op, IORING_OP_RECV | IORING_OP_RECVMSG) || inq == 0 { return 0; }
    super::ops::IORING_CQE_F_SOCK_NONEMPTY
}

/// What one pass of a multishot receive does next.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Step {
    /// Report the delivery with "more follows" and take another pass.
    More,
    /// Report the delivery with "more follows", then arm the description: the
    /// socket handed over everything it had, so a further pass would only
    /// find nothing.
    PostThenWait,
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

/// Decide one pass of a multishot receive from what the transfer returned,
/// whether the socket still holds data, and how many passes this run has
/// already made.
///
/// A zero-length delivery ends it: the peer is finished, and a request left
/// armed on a description that reports readiness forever would spin. A
/// failure ends it too, and its errno is the terminal completion — including
/// the one the group runs dry with, which is the ordinary way a multishot
/// receive stops.
///
/// A delivery that drained the socket goes back to waiting rather than taking
/// another pass: the pass would draw a buffer from the caller's group, find
/// nothing, and hand the buffer straight back. That is the whole value of
/// knowing the queue is empty. # C: O(1)
pub fn step(res: i64, passes: u32, nonempty: bool) -> Step {
    if res == eagain() { return Step::Wait; }
    if res <= 0 { return Step::Done(res); }
    if !nonempty { return Step::PostThenWait; }
    if passes + 1 >= MULTISHOT_MAX_RETRY { return Step::Yield; }
    Step::More
}

/// Decide one pass of an intrinsically multishot file read. Unlike a socket,
/// a file has no queue-length flag to consult: every positive read is another
/// delivery, `EAGAIN` hands the request to poll, and EOF or another error is
/// the terminal completion. # C: O(1)
pub fn read_step(res: i64, passes: u32) -> Step {
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
