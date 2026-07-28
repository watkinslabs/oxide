// `SPLICE_F_*` (Linux `include/linux/splice.h:17-24` — NOT in uapi/fcntl.h)
// and the pure admission decisions of `do_splice`, `do_tee` and `vmsplice`.
// No fd or task access, so the ORDER of every EINVAL/ESPIPE/EBADF is unit
// tested hosted.

use syscall::errno::Errno;

/// `SPLICE_F_MOVE` — move pages instead of copying where the backend can.
pub const SPLICE_F_MOVE:     u64 = 0x01;
/// `SPLICE_F_NONBLOCK` — do not block; `EAGAIN` instead. Note this is ORed with
/// `O_NONBLOCK` from EITHER description in `do_splice` (`fs/splice.c:1323`).
pub const SPLICE_F_NONBLOCK: u64 = 0x02;
/// `SPLICE_F_MORE` — more data is coming (a hint to the network stack).
pub const SPLICE_F_MORE:     u64 = 0x04;
/// `SPLICE_F_GIFT` — the pages are a gift to the kernel and MAY be stolen.
/// Meaningful only to `vmsplice`; `splice`/`tee` accept it and ignore it.
pub const SPLICE_F_GIFT:     u64 = 0x08;
/// `SPLICE_F_ALL` — every other bit is `EINVAL` in all three syscalls.
pub const SPLICE_F_ALL: u64 = SPLICE_F_MOVE | SPLICE_F_NONBLOCK | SPLICE_F_MORE | SPLICE_F_GIFT;

/// Which of the three transfer shapes `do_splice` selects (`fs/splice.c:1315-1382`).
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

/// `do_splice()` admission (`fs/splice.c:1300-1382`) in Linux's exact order.
///
/// The pipe-side ESPIPE checks fire in `__do_splice` BEFORE the offsets are
/// even copied in (`fs/splice.c:1409-1418`), so they precede any EFAULT; the
/// FMODE_READ/WRITE pair is next (`:1308-1310`); then the per-case rules. Note
/// the asymmetry Linux deliberately keeps: an offset supplied for a PIPE end is
/// `ESPIPE`, but an offset supplied for a non-seekable FILE end is `EINVAL`
/// (`:1330-1336`, `:1359-1365`), and `O_APPEND` on the output is `EINVAL`
/// (`:1338`) — not EBADF as in `copy_file_range`. # C: O(1)
pub fn splice_case(i: &SpliceIn) -> Result<SpliceCase, Errno> {
    // `__do_splice`: an offset for a pipe end is meaningless.
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
    // Neither end is a pipe (`fs/splice.c:1380-1382`).
    Err(Errno::Einval)
}

/// `do_tee()` admission (`fs/splice.c:1938-1953`). The FMODE pair is checked
/// BEFORE the pipe test, and "not a pipe" / "same pipe" share one EINVAL (the
/// function's initialiser `ret = -EINVAL` falls through for both). # C: O(1)
pub fn tee_admit(in_is_pipe: bool, out_is_pipe: bool, same_pipe: bool,
                 in_readable: bool, out_writable: bool) -> Result<(), Errno> {
    if !in_readable || !out_writable { return Err(Errno::Ebadf); }
    if !in_is_pipe || !out_is_pipe || same_pipe { return Err(Errno::Einval); }
    Ok(())
}

/// `vmsplice` transfer direction, chosen PURELY from `f_mode`
/// (`fs/splice.c:1593-1598`) — not from whether the fd happens to be a read or
/// write pipe end. A description that is both readable and writable splices
/// user memory INTO the pipe.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum VmspliceDir {
    /// `ITER_SOURCE` — user pages into the pipe (`vmsplice_to_pipe`).
    ToPipe,
    /// `ITER_DEST` — pipe bytes out to user memory (`vmsplice_to_user`).
    ToUser,
}

/// Direction selection. `EBADF` when the description is neither readable nor
/// writable (an `O_PATH` fd). Whether the fd is actually a PIPE is decided
/// later, inside the direction helpers, and is also `EBADF`, never `EINVAL`
/// (`fs/splice.c:1512`, `:1545`). # C: O(1)
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
    /// looks like the same mistake — `fs/splice.c:1409-1418` vs `:1330`/`:1359`.
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

    /// `O_APPEND` on a splice OUTPUT is EINVAL (`fs/splice.c:1338`), checked
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
