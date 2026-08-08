// `SPLICE_F_*` flag bits and the pure admission decisions of `splice`, `tee`
// and `vmsplice`.
// No fd or task access, so the ORDER of every EINVAL/ESPIPE/EBADF is unit
// tested hosted.

use syscall::errno::Errno;

/// `SPLICE_F_MOVE` — move pages instead of copying where the backend can.
pub const SPLICE_F_MOVE:     u64 = 0x01;
/// `SPLICE_F_NONBLOCK` — do not block; `EAGAIN` instead. Note this is ORed with
/// `O_NONBLOCK` from EITHER description in the `splice` admission path.
pub const SPLICE_F_NONBLOCK: u64 = 0x02;
/// `SPLICE_F_MORE` — more data is coming (a hint to the network stack).
pub const SPLICE_F_MORE:     u64 = 0x04;
/// `SPLICE_F_GIFT` — the pages are a gift to the kernel and MAY be stolen.
/// Meaningful only to `vmsplice`; `splice`/`tee` accept it and ignore it.
pub const SPLICE_F_GIFT:     u64 = 0x08;
/// `SPLICE_F_ALL` — every other bit is `EINVAL` in all three syscalls.
pub const SPLICE_F_ALL: u64 = SPLICE_F_MOVE | SPLICE_F_NONBLOCK | SPLICE_F_MORE | SPLICE_F_GIFT;

/// Which of the three transfer shapes `splice(2)` selects.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SpliceCase {
    /// Both ends are pipes — `splice_pipe_to_pipe`.
    PipeToPipe,
    /// Input is a pipe, output is a file — `do_splice_from`.
    PipeToFile,
    /// Output is a pipe, input is a file — `splice_file_to_pipe`.
    FileToPipe,
}

/// The facts `do_splice` decides on, gathered by the caller from the two
/// descriptions.
#[derive(Copy, Clone, Debug)]
pub struct SpliceIn {
    pub in_is_pipe: bool,
    pub out_is_pipe: bool,
    /// The two ends resolve to the SAME pipe ring (`ipipe == opipe`).
    pub same_pipe: bool,
    pub in_readable: bool,
    pub out_writable: bool,
    /// A non-NULL `off_in` / `off_out` user pointer was supplied.
    pub off_in: bool,
    pub off_out: bool,
    /// `FMODE_PREAD` / `FMODE_PWRITE` on the non-pipe end.
    pub in_pread: bool,
    pub out_pwrite: bool,
    /// `O_APPEND` on the output description.
    pub out_append: bool,
}

/// `splice(2)` admission ladder. Order:
/// 1. An offset supplied for a PIPE end (either side) is `ESPIPE` — checked
/// BEFORE the offsets are even copied in, so this precedes any EFAULT.
/// 2. The FMODE_READ/FMODE_WRITE pair is `EBADF`.
/// 3. Per-case rules: an offset supplied for a non-seekable FILE end is
/// `EINVAL` (the asymmetry with step 1 is deliberate — pipe-end offset is
/// ESPIPE, file-end non-seekable offset is EINVAL), and `O_APPEND` on the
/// output is `EINVAL` — not EBADF as in `copy_file_range`. # C: O(1)
pub fn splice_case(i: &SpliceIn) -> Result<SpliceCase, Errno> {
    // An offset for a pipe end is meaningless.
    if i.in_is_pipe && i.off_in { return Err(Errno::Espipe); }
    if i.out_is_pipe && i.off_out { return Err(Errno::Espipe); }
    if !i.in_readable || !i.out_writable { return Err(Errno::Ebadf); }
    if i.in_is_pipe && i.out_is_pipe {
        // Splicing a pipe to itself would deadlock on its own lock.
        if i.same_pipe { return Err(Errno::Einval); }
        return Ok(SpliceCase::PipeToPipe);
    }
    if i.in_is_pipe {
        if i.off_out && !i.out_pwrite { return Err(Errno::Einval); }
        if i.out_append { return Err(Errno::Einval); }
        return Ok(SpliceCase::PipeToFile);
    }
    if i.out_is_pipe {
        if i.off_in && !i.in_pread { return Err(Errno::Einval); }
        return Ok(SpliceCase::FileToPipe);
    }
    // Neither end is a pipe.
    Err(Errno::Einval)
}

/// The MORE-DATA hint one pipe→output batch carries.
///
/// Two independent reasons, ORed, and BOTH are part of the contract:
/// 1. the caller set `SPLICE_F_MORE`, which holds for every batch of the call;
/// 2. this batch did not exhaust the request (`seg < req`) AND the pipe still
///    holds bytes past the batch (`queued > seg`) — so another batch is going
///    out of this same call and the segment about to be written is not the last
///    one. Deriving (2) is what stops a multi-batch splice from emitting one
///    short segment per batch even when the caller passed no flag at all.
///
/// `seg` is the byte count this batch will hand the output, `req` the bytes
/// still wanted by the call, `queued` the bytes currently in the input pipe.
/// # C: O(1)
pub fn more_hint(user_more: bool, req: usize, seg: usize, queued: usize) -> bool {
    user_more || (seg < req && queued > seg)
}

/// `tee(2)` admission. The FMODE pair is checked
/// BEFORE the pipe test, and "not a pipe" / "same pipe" share one EINVAL. # C: O(1)
pub fn tee_admit(in_is_pipe: bool, out_is_pipe: bool, same_pipe: bool,
                 in_readable: bool, out_writable: bool) -> Result<(), Errno> {
    if !in_readable || !out_writable { return Err(Errno::Ebadf); }
    if !in_is_pipe || !out_is_pipe || same_pipe { return Err(Errno::Einval); }
    Ok(())
}

/// `vmsplice` transfer direction, chosen PURELY from `f_mode` — not from
/// whether the fd happens to be a read or write pipe end. A description that
/// is both readable and writable splices user memory INTO the pipe.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum VmspliceDir {
    /// User pages into the pipe.
    ToPipe,
    /// Pipe bytes out to user memory.
    ToUser,
}

/// Direction selection. `EBADF` when the description is neither readable nor
/// writable (an `O_PATH` fd). Whether the fd is actually a PIPE is decided
/// later, inside the direction helpers, and is also `EBADF`, never `EINVAL`.
/// # C: O(1)
pub fn vmsplice_dir(writable: bool, readable: bool) -> Result<VmspliceDir, Errno> {
    if writable { return Ok(VmspliceDir::ToPipe); }
    if readable { return Ok(VmspliceDir::ToUser); }
    Err(Errno::Ebadf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> SpliceIn {
        SpliceIn { in_is_pipe: false, out_is_pipe: false, same_pipe: false,
            in_readable: true, out_writable: true, off_in: false, off_out: false,
            in_pread: true, out_pwrite: true, out_append: false }
    }

    /// `SPLICE_F_ALL` is exactly the four documented bits. # C: O(1)
    #[test]
    fn splice_flag_set() {
        assert_eq!(SPLICE_F_ALL, 0x0f);
        assert_eq!((SPLICE_F_MOVE, SPLICE_F_NONBLOCK, SPLICE_F_MORE, SPLICE_F_GIFT),
                   (1, 2, 4, 8));
    }

    /// Neither end a pipe → EINVAL. This is the rule the pre-fix implementation
    /// had NO trace of: it ran a read/write loop between any two fds, so
    /// `splice(regular, regular)` silently copied data where Linux refuses.
    /// # C: O(1)
    #[test]
    fn neither_end_a_pipe_is_einval() {
        assert_eq!(splice_case(&base()), Err(Errno::Einval));
        // ... and it stays EINVAL whatever the offsets say.
        let i = SpliceIn { off_in: true, off_out: true, ..base() };
        assert_eq!(splice_case(&i), Err(Errno::Einval));
    }

    /// Case selection for the three legal shapes, and the same-pipe rejection.
    /// # C: O(1)
    #[test]
    fn three_cases_and_self_splice() {
        let p2p = SpliceIn { in_is_pipe: true, out_is_pipe: true, ..base() };
        assert_eq!(splice_case(&p2p), Ok(SpliceCase::PipeToPipe));
        assert_eq!(splice_case(&SpliceIn { same_pipe: true, ..p2p }), Err(Errno::Einval));
        assert_eq!(splice_case(&SpliceIn { in_is_pipe: true, ..base() }), Ok(SpliceCase::PipeToFile));
        assert_eq!(splice_case(&SpliceIn { out_is_pipe: true, ..base() }), Ok(SpliceCase::FileToPipe));
    }

    /// An offset for a PIPE end is ESPIPE and beats the FMODE check; an offset
    /// for a non-seekable FILE end is EINVAL. Two different errnos for what
    /// looks like the same mistake — the pipe-offset check and the file-end
    /// seekability check are two distinct steps in the admission ladder.
    /// # C: O(1)
    #[test]
    fn offset_rules_espipe_for_pipes_einval_for_files() {
        let i = SpliceIn { in_is_pipe: true, off_in: true, in_readable: false, ..base() };
        assert_eq!(splice_case(&i), Err(Errno::Espipe), "ESPIPE precedes the EBADF gate");
        let i = SpliceIn { out_is_pipe: true, off_out: true, ..base() };
        assert_eq!(splice_case(&i), Err(Errno::Espipe));
        // Non-seekable file end with an offset → EINVAL.
        let i = SpliceIn { in_is_pipe: true, off_out: true, out_pwrite: false, ..base() };
        assert_eq!(splice_case(&i), Err(Errno::Einval));
        let i = SpliceIn { out_is_pipe: true, off_in: true, in_pread: false, ..base() };
        assert_eq!(splice_case(&i), Err(Errno::Einval));
        // Seekable file end with an offset is fine.
        assert_eq!(splice_case(&SpliceIn { in_is_pipe: true, off_out: true, ..base() }),
                   Ok(SpliceCase::PipeToFile));
    }

    /// `O_APPEND` on a splice OUTPUT is EINVAL, checked
    /// after the FMODE_PWRITE rule; unlike `copy_file_range`, where the same
    /// condition is EBADF. # C: O(1)
    #[test]
    fn append_output_is_einval() {
        let i = SpliceIn { in_is_pipe: true, out_append: true, ..base() };
        assert_eq!(splice_case(&i), Err(Errno::Einval));
        // Only applies to the pipe->file case; an append pipe output is moot.
        let i = SpliceIn { out_is_pipe: true, out_append: true, ..base() };
        assert_eq!(splice_case(&i), Ok(SpliceCase::FileToPipe));
    }

    /// FMODE_READ/FMODE_WRITE → EBADF, checked before the per-case rules but
    /// after the pipe-offset ESPIPE. # C: O(1)
    #[test]
    fn fmode_gate_is_ebadf() {
        let i = SpliceIn { in_is_pipe: true, in_readable: false, ..base() };
        assert_eq!(splice_case(&i), Err(Errno::Ebadf));
        let i = SpliceIn { out_is_pipe: true, out_writable: false, ..base() };
        assert_eq!(splice_case(&i), Err(Errno::Ebadf));
    }

    /// `tee` needs BOTH ends to be distinct pipes; the FMODE gate comes first.
    /// # C: O(1)
    #[test]
    fn tee_needs_two_distinct_pipes() {
        assert_eq!(tee_admit(true, true, false, true, true), Ok(()));
        assert_eq!(tee_admit(true, true, true, true, true), Err(Errno::Einval), "same pipe");
        assert_eq!(tee_admit(false, true, false, true, true), Err(Errno::Einval));
        assert_eq!(tee_admit(true, false, false, true, true), Err(Errno::Einval));
        assert_eq!(tee_admit(false, false, false, false, true), Err(Errno::Ebadf),
            "EBADF precedes the pipe test");
        assert_eq!(tee_admit(true, true, false, true, false), Err(Errno::Ebadf));
    }

    /// `SPLICE_F_MORE` from the caller marks EVERY batch, whatever the batch
    /// and pipe sizes say — the caller is promising data beyond this whole
    /// call, which no amount of local emptiness can contradict. # C: O(1)
    #[test]
    fn user_more_marks_every_batch() {
        // Last batch: exhausts the request and drains the pipe.
        assert!(more_hint(true, 100, 100, 100));
        // Not even a full batch's worth left.
        assert!(more_hint(true, 4096, 10, 10));
        assert!(more_hint(true, 0, 0, 0));
    }

    /// Without the caller's flag the hint is DERIVED, and needs both halves:
    /// the batch left request bytes unfilled AND the pipe still holds bytes
    /// past this batch. Either half alone means this segment is the last one
    /// this call will produce, so it must go out unhinted or the output sits
    /// on it. # C: O(1)
    #[test]
    fn derived_more_needs_request_and_pipe_remainder() {
        // Both halves: 4096-byte batch out of a 8192 request, 8192 queued.
        assert!(more_hint(false, 8192, 4096, 8192));
        // Request satisfied by this batch — nothing more is coming from here,
        // even though the pipe holds more than the batch.
        assert!(!more_hint(false, 4096, 4096, 8192));
        // Request unfinished but the pipe is drained by this batch: the next
        // round has nothing to send until a writer refills, so this segment is
        // final as far as this call knows.
        assert!(!more_hint(false, 8192, 4096, 4096));
        // Neither half.
        assert!(!more_hint(false, 100, 100, 100));
        // A zero-length batch cannot claim more data is queued past it.
        assert!(!more_hint(false, 8192, 0, 0));
    }

    /// The derived half is what a multi-batch splice with NO flags relies on:
    /// every batch but the last is hinted, the last is not. Walking a whole
    /// 3-batch transfer pins the boundary that a per-batch write would
    /// otherwise turn into three separate segments. # C: O(1)
    #[test]
    fn multi_batch_hints_all_but_the_last() {
        const BATCH: usize = 4096;
        let queued = 3 * BATCH;      // whole transfer sitting in the pipe
        let mut req = 3 * BATCH;
        let mut left = queued;
        let mut hints = [false; 3];
        for h in hints.iter_mut() {
            let seg = BATCH.min(left).min(req);
            *h = more_hint(false, req, seg, left);
            req -= seg;
            left -= seg;
        }
        assert_eq!(hints, [true, true, false]);
    }

    /// vmsplice direction is decided by `f_mode` alone, and an `O_PATH` fd
    /// (neither bit) is EBADF — not EINVAL. # C: O(1)
    #[test]
    fn vmsplice_direction_from_fmode() {
        assert_eq!(vmsplice_dir(true, false), Ok(VmspliceDir::ToPipe));
        assert_eq!(vmsplice_dir(true, true), Ok(VmspliceDir::ToPipe), "writable wins");
        assert_eq!(vmsplice_dir(false, true), Ok(VmspliceDir::ToUser));
        assert_eq!(vmsplice_dir(false, false), Err(Errno::Ebadf));
    }
}
