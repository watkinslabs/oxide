// `tee(2)` work-fn: admission, prep both pipe ends, then a non-consuming
// pipe-to-pipe link.

use vfs::{File, OpenFlags};

use super::flags::{tee_admit, SPLICE_F_NONBLOCK};
use super::pipe_xfer::err;
use crate::pipe;

/// One `tee(2)` call over already-resolved descriptions.
///
/// `tee` DUPLICATES: the bytes it copies into `out_file` stay queued in
/// `in_file` for a later reader. The pre-fix implementation forwarded to the
/// splice read/write loop, which CONSUMED the input — so `tee` destroyed the
/// data it was asked to preserve, and the shell idiom it exists for
/// (`tee` a pipe, then still read it) silently lost every byte.
///
/// Input EOF (all writers closed) returns 0 even with `SPLICE_F_NONBLOCK`;
/// an empty pipe with writers still open returns `EAGAIN` when non-blocking.
/// # C: O(len)
pub fn do_tee(in_file: &File, out_file: &File, len: usize, flags: u64) -> i64 {
    let ipipe = pipe::pipe_info(in_file);
    let opipe = pipe::pipe_info(out_file);
    let same = match (&ipipe, &opipe) {
        (Some(a), Some(b)) => core::ptr::eq(&**a as *const _, &**b as *const _),
        _ => false,
    };
    if let Err(e) = tee_admit(ipipe.is_some(), opipe.is_some(), same,
                              in_file.f_mode().contains(vfs::Fmode::READ),
                              out_file.f_mode().contains(vfs::Fmode::WRITE)) {
        return -(e.as_i32() as i64);
    }
    let (inp, out) = (ipipe.as_deref().unwrap(), opipe.as_deref().unwrap());
    let nonblock = flags & SPLICE_F_NONBLOCK != 0
        || in_file.flags().contains(OpenFlags::O_NONBLOCK)
        || out_file.flags().contains(OpenFlags::O_NONBLOCK);
    // Prep order: input readiness first, then output readiness, then the link.
    match pipe::ipipe_prep(inp, nonblock) {
        Ok(true)  => {}
        Ok(false) => return 0,                       // EOF: all writers gone
        Err(e)    => return err(e),
    }
    if let Err(e) = pipe::opipe_prep(out, nonblock) { return err(e); }
    let n = pipe::link_pipe(inp, out, len, /*consume*/ false);
    if n > 0 {
        // Only the OUTPUT gains readable bytes; the input is untouched, so its
        // write-side waiters must NOT be woken (nothing was freed).
        pipe::wake_readers(out, out_file.inode());
    }
    n as i64
}
