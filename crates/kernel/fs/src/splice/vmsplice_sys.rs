// `SYSCALL_DEFINE4(vmsplice)` (Linux `fs/splice.c:1578-1614`) →
// `vmsplice_to_pipe` (`:1531-1560`) / `vmsplice_to_user` (`:1501-1527`).
//
// Both directions exist in this tree; the direction is chosen from `f_mode`
// alone (`fs/splice.c:1593-1598`), never from the caller's intent. The pre-fix
// implementation only ever wrote, so `vmsplice` on a READ pipe end appended the
// caller's buffer to the pipe instead of draining it into the caller.

use vfs::{File, OpenFlags};

use super::flags::SPLICE_F_NONBLOCK;
use super::pipe_xfer::err;
use crate::pipe;

/// `SPLICE_F_NONBLOCK` plus the description's own `O_NONBLOCK`. # C: O(1)
fn nonblocking(file: &File, flags: u64) -> bool {
    flags & SPLICE_F_NONBLOCK != 0 || file.flags().contains(OpenFlags::O_NONBLOCK)
}

/// `vmsplice_to_pipe` — user pages into the pipe. Returns the byte count, or
/// `-errno` when nothing was transferred.
///
/// `add_to_pipe` never blocks mid-vector (`fs/splice.c:245-263`): once the ring
/// fills, the accumulated count is returned rather than waiting, so a large
/// vmsplice into a small pipe is a legal short transfer. `SPLICE_F_GIFT` only
/// authorises a downstream consumer to STEAL the page; with a copying ring
/// there is nothing to steal, so it changes no observable behaviour.
/// # C: O(sum of buf lens)
pub fn do_vmsplice_to_pipe(file: &File, bufs: &[&[u8]], flags: u64) -> i64 {
    // `!pipe` → EBADF, not EINVAL (`fs/splice.c:1545-1546`).
    let Some(p) = pipe::pipe_info(file) else { return -(syscall::errno::Errno::Ebadf.as_i32() as i64) };
    let total_in: usize = bufs.iter().map(|b| b.len()).sum();
    if total_in == 0 { return 0; }
    let nonblock = nonblocking(file, flags);
    // `wait_for_space` once up front (`fs/splice.c:1551`): EPIPE (+SIGPIPE) when
    // no readers remain, EAGAIN when non-blocking and full, ERESTARTSYS on a
    // pending signal.
    if let Err(e) = pipe::opipe_prep(&p, nonblock) { return err(e); }
    let mut total = 0usize;
    for b in bufs {
        let mut off = 0usize;
        while off < b.len() {
            let n = pipe::fill(&p, &b[off..]);
            if n == 0 { break; }
            off += n;
            total += n;
        }
        if off < b.len() { break; }
    }
    if total > 0 { pipe::wake_readers(&p, file.inode()); }
    total as i64
}

/// `vmsplice_to_user` — pipe bytes out into user memory. A plain copy in Linux
/// too (`pipe_to_user`, `fs/splice.c:1490-1495`). # C: O(sum of buf lens)
pub fn do_vmsplice_to_user(file: &File, bufs: &mut [&mut [u8]], flags: u64) -> i64 {
    let Some(p) = pipe::pipe_info(file) else { return -(syscall::errno::Errno::Ebadf.as_i32() as i64) };
    let total_in: usize = bufs.iter().map(|b| b.len()).sum();
    if total_in == 0 { return 0; }
    let nonblock = nonblocking(file, flags);
    match pipe::ipipe_prep(&p, nonblock) {
        Ok(true)  => {}
        Ok(false) => return 0,                       // EOF: all writers gone
        Err(e)    => return err(e),
    }
    let mut total = 0usize;
    for b in bufs.iter_mut() {
        let n = pipe::peek(&p, b);
        if n == 0 { break; }
        pipe::advance(&p, n);
        total += n;
        if n < b.len() { break; }
    }
    if total > 0 { pipe::wake_writers(&p, file.inode()); }
    total as i64
}
