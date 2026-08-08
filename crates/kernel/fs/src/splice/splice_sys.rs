// `splice(2)` work-fn: case selection, nonblock derivation, and the
// transfer loop over the resolved descriptions.

use syscall::errno::Errno;
use vfs::{File, OpenFlags};

use super::flags::{splice_case, SpliceCase, SpliceIn, SPLICE_F_MORE, SPLICE_F_NONBLOCK};
use super::pipe_xfer::{err, file_to_pipe, pipe_to_file, pipe_to_pipe};
use crate::pipe;

fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// One `splice(2)` call over already-resolved descriptions.
///
/// `off_in`/`off_out` are `Option<&mut u64>`: `Some` mirrors a non-NULL user
/// pointer whose value the shim copied in and will copy back on success —
/// copy-out happens only for `ret >= 0`.
///
/// The transfer loop runs until `len` is satisfied, the input hits EOF, or a
/// stall. Already-moved bytes beat a pending errno: EAGAIN/ERESTARTSYS/
/// EPIPE surface only when nothing has moved yet. # C: O(len)
pub fn do_splice(in_file: &File, off_in: Option<&mut u64>,
                 out_file: &File, off_out: Option<&mut u64>,
                 len: usize, flags: u64) -> i64 {
    let ipipe = pipe::pipe_info(in_file);
    let opipe = pipe::pipe_info(out_file);
    let same = match (&ipipe, &opipe) {
        (Some(a), Some(b)) => core::ptr::eq(&**a as *const _, &**b as *const _),
        _ => false,
    };
    let sin = SpliceIn {
        in_is_pipe: ipipe.is_some(),
        out_is_pipe: opipe.is_some(),
        same_pipe: same,
        in_readable: in_file.f_mode().contains(vfs::Fmode::READ),
        out_writable: out_file.f_mode().contains(vfs::Fmode::WRITE),
        off_in: off_in.is_some(),
        off_out: off_out.is_some(),
        in_pread: in_file.f_mode().contains(vfs::Fmode::PREAD),
        out_pwrite: out_file.f_mode().contains(vfs::Fmode::PWRITE),
        out_append: out_file.flags().contains(OpenFlags::O_APPEND),
    };
    let case = match splice_case(&sin) { Ok(c) => c, Err(e) => return errno(e) };
    // `O_NONBLOCK` on EITHER description adds SPLICE_F_NONBLOCK.
    let nonblock = flags & SPLICE_F_NONBLOCK != 0
        || in_file.flags().contains(OpenFlags::O_NONBLOCK)
        || out_file.flags().contains(OpenFlags::O_NONBLOCK);
    // `SPLICE_F_MORE` marks every batch of this call; a batch followed by
    // another batch of the same call is marked too, decided per batch.
    let user_more = flags & SPLICE_F_MORE != 0;

    let mut total: usize = 0;
    // Explicit-offset ends work on a local cursor that the caller writes back;
    // otherwise the description's own `f_pos` moves.
    let mut in_pos = off_in.as_ref().map(|p| **p).unwrap_or(0);
    let mut out_pos = off_out.as_ref().map(|p| **p).unwrap_or(0);
    let use_in_pos = off_in.is_some();
    let use_out_pos = off_out.is_some();

    while total < len {
        let want = len - total;
        let r = match case {
            SpliceCase::PipeToPipe => pipe_to_pipe(
                ipipe.as_deref().unwrap(), in_file, opipe.as_deref().unwrap(), out_file, want, nonblock),
            SpliceCase::PipeToFile => pipe_to_file(
                ipipe.as_deref().unwrap(), in_file, out_file, &mut out_pos, use_out_pos, want, nonblock,
                user_more),
            SpliceCase::FileToPipe => file_to_pipe(
                in_file, &mut in_pos, use_in_pos, opipe.as_deref().unwrap(), out_file, want, nonblock),
        };
        match r {
            Ok(0)                => break,                       // EOF / no progress
            Ok(n)                => total += n,
            Err(e) if total == 0 => return err(e),
            Err(_)               => break,                       // partial count wins
        }
        // One batch is all a non-blocking caller is promised; looping would
        // re-enter the wait states and could return EAGAIN after progress.
        if nonblock { break; }
    }
    if let Some(p) = off_in { *p = in_pos; }
    if let Some(p) = off_out { *p = out_pos; }
    total as i64
}
