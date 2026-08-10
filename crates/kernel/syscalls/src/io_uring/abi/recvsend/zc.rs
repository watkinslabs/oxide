// `IORING_OP_SEND_ZC` / `IORING_OP_SENDMSG_ZC` — a send that posts TWO
// completions.
//
// An ordinary send returns once the payload has been taken out of the
// caller's memory, which is why the caller may reuse that memory the moment
// the completion arrives. A zero-copy send does not promise that: it returns
// as soon as the bytes are ACCOUNTED FOR, and the payload memory stays live
// until the network stack is finished with it. So the caller gets two
// completions for one submission:
//
//   * the send's own result, carrying `IORING_CQE_F_MORE` — "there is another
//     completion for this submission";
//   * the NOTIFICATION, carrying `IORING_CQE_F_NOTIF` — "the payload memory is
//     yours again". Its `user_data` is the entry's `addr3` when it names one,
//     so a caller can route notifications separately from results, and the
//     entry's own `user_data` otherwise.
//
// `IORING_SEND_ZC_REPORT_USAGE` asks the notification to say whether the
// payload was actually handed over without a copy: `IORING_NOTIF_USAGE_ZC_COPIED`
// in its result means it was copied after all, which is what a caller measures
// before deciding the extra completion is worth paying for. It is refused on
// the ORDINARY send opcodes — they post no notification, so there is nothing
// there for it to describe.
//
// Ungated: the flag ladder, the notification's identity and its result word
// are decisions, and the file that runs the send is kernel-gated (CLAUDE.md
// phantom-test rule).

use syscall::errno::Errno;

use crate::io_uring_abi::ops::{IORING_NOTIF_USAGE_ZC_COPIED, IORING_OP_SEND_ZC,
                               IORING_OP_SENDMSG_ZC, IOSQE_CQE_SKIP_SUCCESS};

use super::{FIXED_BUF, POLL_FIRST, SEND_VECTORIZED, SEND_ZC_REPORT_USAGE};

/// The bits a zero-copy send's flag word accepts.
pub const ZC_FLAGS: u16 = POLL_FIRST | FIXED_BUF | SEND_ZC_REPORT_USAGE | SEND_VECTORIZED;

/// Whether this opcode is a zero-copy send. # C: O(1)
pub fn is_zc(op: u8) -> bool { matches!(op, IORING_OP_SEND_ZC | IORING_OP_SENDMSG_ZC) }

/// The notification a zero-copy send will post.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Notif {
    /// What the notification completion is reported under.
    pub user_data: u64,
    /// The notification reports whether the payload was copied.
    pub report_usage: bool,
}

/// The zero-copy send's admission ladder.
///
/// | rung | errno |
/// |---|---|
/// | a bit outside the zero-copy flag word | `EINVAL` |
/// | silent success asked for | `EINVAL` |
/// | a message-carrying form naming a destination address or a slot | `EINVAL` |
///
/// Silent success is refused because it would suppress the send's own
/// completion while the notification still arrived — the caller would see one
/// completion it never asked for and could not match. A message-carrying send
/// already names its destination inside the header, so an address beside it is
/// a second answer. # C: O(1)
pub fn admit(op: u8, sqe_flags: u8, ioprio: u16, addr2: u64, file_index: u32)
    -> Result<(), Errno>
{
    if !is_zc(op) { return Ok(()); }
    if ioprio & !ZC_FLAGS != 0 { return Err(Errno::Einval); }
    if sqe_flags & IOSQE_CQE_SKIP_SUCCESS != 0 { return Err(Errno::Einval); }
    if op == IORING_OP_SENDMSG_ZC && (addr2 != 0 || file_index != 0) {
        return Err(Errno::Einval);
    }
    Ok(())
}

/// The notification this entry will post. `addr3` names it when the caller
/// wants notifications distinguishable from results; otherwise it shares the
/// entry's own identity, and the `IORING_CQE_F_NOTIF` flag is what tells the
/// two apart. # C: O(1)
pub fn notif(user_data: u64, addr3: u64, ioprio: u16) -> Notif {
    Notif {
        user_data: if addr3 != 0 { addr3 } else { user_data },
        report_usage: ioprio & SEND_ZC_REPORT_USAGE != 0,
    }
}

/// The notification's result word.
///
/// Zero unless the caller asked to be told how the payload travelled, and the
/// copied bit when it did not travel by reference. A caller that did not ask
/// gets a plain zero, so the field stays free for it to ignore. # C: O(1)
pub fn notif_res(report_usage: bool, copied: bool) -> i32 {
    if report_usage && copied { IORING_NOTIF_USAGE_ZC_COPIED as i32 } else { 0 }
}

#[cfg(test)]
#[path = "zc_tests.rs"]
mod tests;
