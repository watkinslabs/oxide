// Pipe-side primitives `splice(2)`/`tee(2)`/`vmsplice(2)` need and that a
// plain read/write cannot express: a NON-consuming ring-to-ring duplication
// (Linux `link_pipe`, `fs/splice.c:1850-1930`) and the three wait states
// (`ipipe_prep` `:1642-1672`, `opipe_prep` `:1678-1711`, `wait_for_space`
// `:1259-1274`), whose errno ORDER differs between them.

use core::sync::atomic::Ordering;

use vfs::{File, FileType, KResult, VfsError};

use super::ring::{pipe_data, PipeData};
use super::{fifo_pipe_lookup, is_named_fifo};

/// A resolved pipe ring: borrowed from the inode for an anonymous pipe, owned
/// for a named FIFO (whose ring lives in the side table). Derefs to
/// [`PipeData`] so callers never care which.
pub enum PipeRef<'a> {
    Anon(&'a PipeData),
    Fifo(alloc::sync::Arc<PipeData>),
}

impl core::ops::Deref for PipeRef<'_> {
    type Target = PipeData;
    /// # C: O(1)
    fn deref(&self) -> &PipeData {
        match self { PipeRef::Anon(p) => p, PipeRef::Fifo(p) => p }
    }
}

/// `get_pipe_info(file, for_splice)` (Linux `fs/pipe.c:1512-1523`): the ring
/// behind a description IFF it really is a pipe end. Covers both an anonymous
/// pipe (ring in `i_private`) and an opened named FIFO (ring in the per-inode
/// side table). Anything else — a regular file, a socket, an eventfd, a FIFO
/// inode nobody has opened — is `None`, which is what makes the "at least one
/// end must be a pipe" rule decidable. # C: O(log N)
pub fn pipe_info(file: &File) -> Option<PipeRef<'_>> {
    let inode = file.inode();
    if inode.file_type() != FileType::Fifo { return None; }
    if let Some(p) = pipe_data(inode) { return Some(PipeRef::Anon(p)); }
    if is_named_fifo(inode) { return fifo_pipe_lookup(inode).map(PipeRef::Fifo); }
    None
}

/// Bytes currently queued. # C: O(1)
pub fn queued(p: &PipeData) -> usize { p.buf.lock().len }

/// Free bytes before the ring is full. # C: O(1)
pub fn space(p: &PipeData) -> usize {
    let g = p.buf.lock();
    g.cap.saturating_sub(g.len)
}

/// Move or duplicate up to `len` bytes from `src` into `dst`.
///
/// `consume == false` is Linux `link_pipe()` (the `tee(2)` engine): the bytes
/// stay queued in `src`. Linux achieves that by taking a REFERENCE on the pipe
/// buffer pages; oxide's ring is a byte array, so the duplication is a copy —
/// observably identical, since `link_pipe` also strips `PIPE_BUF_FLAG_GIFT` and
/// `PIPE_BUF_FLAG_CAN_MERGE` from the duplicate so the page can never be stolen
/// twice (`fs/splice.c:1907-1908`).
///
/// `consume == true` is the `splice_pipe_to_pipe()` move.
///
/// BOTH rings are locked for the whole transfer, so a concurrent reader cannot
/// drain `src` mid-copy and leave `dst` holding bytes that were also delivered
/// elsewhere. The two locks are taken in ADDRESS order, which is what makes two
/// crossing `tee(a,b)` / `tee(b,a)` calls deadlock-free — they share one lock
/// class, so rank alone does not order them. # C: O(bytes)
pub fn link_pipe(src: &PipeData, dst: &PipeData, len: usize, consume: bool) -> usize {
    if core::ptr::eq(src, dst) { return 0; }
    let (first, second) = if (src as *const PipeData as usize) < (dst as *const PipeData as usize) {
        (&src.buf, &dst.buf)
    } else {
        (&dst.buf, &src.buf)
    };
    let mut ga = first.lock();
    let mut gb = second.lock();
    // Re-derive which guard is which now that both are held.
    let src_first = core::ptr::eq(first as *const _, &src.buf as *const _);
    let (s, d) = if src_first { (&mut *ga, &mut *gb) } else { (&mut *gb, &mut *ga) };
    let mut n = 0usize;
    let mut idx = s.head;
    while n < len {
        if n >= s.len { break; }
        if d.len >= d.cap { break; }
        let b = s.data[idx];
        let packet = s.packet[idx];
        let packet_end = s.packet_end[idx];
        if !d.push(b, packet, packet_end) { break; }
        idx = s.next_idx(idx);
        n += 1;
    }
    if consume {
        for _ in 0..n { s.pop(); }
    }
    n
}

/// Copy up to `dst.len()` queued bytes out of `p` WITHOUT consuming them.
///
/// The pipe→file leg of `splice` needs this: Linux moves pipe BUFFERS (page
/// references) into the file write and only releases a buffer once the write
/// has taken it (`__splice_from_pipe` → `pipe_buf_release`), so a short or
/// failed write loses nothing. Draining into a staging buffer first and writing
/// afterwards would destroy the bytes the write did not accept. Peek, write,
/// then [`advance`] by exactly the accepted count. # C: O(bytes)
pub fn peek(p: &PipeData, dst: &mut [u8]) -> usize {
    let g = p.buf.lock();
    let n = dst.len().min(g.len);
    let mut idx = g.head;
    for slot in dst.iter_mut().take(n) {
        *slot = g.data[idx];
        idx = g.next_idx(idx);
    }
    n
}

/// Drop the first `n` queued bytes — the commit half of [`peek`]. # C: O(n)
pub fn advance(p: &PipeData, n: usize) {
    let mut g = p.buf.lock();
    for _ in 0..n { if g.pop().is_none() { break; } }
}

/// Push up to `src.len()` bytes into `p` without blocking, returning the count
/// accepted (0 when the ring is full). The caller has already run
/// [`opipe_prep`], so a full ring here is a race, not an error. # C: O(bytes)
pub fn fill(p: &PipeData, src: &[u8]) -> usize {
    let mut g = p.buf.lock();
    let mut n = 0;
    for &b in src {
        if !g.push(b, false, false) { break; }
        n += 1;
    }
    n
}

/// `ipipe_prep()` (Linux `fs/splice.c:1642-1672`) — make the INPUT pipe ready.
///
/// Order matters and differs from the output side: a pending signal is checked
/// FIRST (`-ERESTARTSYS`), then "all writers gone" is EOF (`Ok(false)`, which
/// the caller turns into a 0 return REGARDLESS of `SPLICE_F_NONBLOCK`), and
/// only then does `SPLICE_F_NONBLOCK` produce `-EAGAIN`. Getting that order
/// wrong turns a closed pipe into a spurious EAGAIN. `Ok(true)` = data queued.
/// # C: O(1) + park
pub fn ipipe_prep(p: &PipeData, nonblock: bool) -> KResult<bool> {
    loop {
        if queued(p) != 0 { return Ok(true); }
        #[cfg(target_os = "oxide-kernel")]
        if sched::live::deliverable_signals_self() != 0 { return Err(VfsError::Erestartsys); }
        if p.writers.load(Ordering::Acquire) == 0 { return Ok(false); } // EOF
        if nonblock { return Err(VfsError::Eagain); }
        #[cfg(target_os = "oxide-kernel")]
        {
            // SAFETY: running task on this CPU; preempt-off; park bumps the Arc
            // and marks the task Sleeping before schedule, and a writer's
            // push+wake_all targets this same read_waiters list.
            unsafe { p.read_waiters.park(); }
            // SAFETY: process ctx; runqueue installed; current is Sleeping until
            // a writer (or the last writer's close) wakes the read side.
            unsafe { sched::live::schedule::schedule(); }
        }
        #[cfg(not(target_os = "oxide-kernel"))]
        return Err(VfsError::Eagain);
    }
}

/// `opipe_prep()` / `wait_for_space()` (Linux `fs/splice.c:1678-1711`,
/// `:1259-1274`) — make the OUTPUT pipe ready.
///
/// Order is the MIRROR of the input side: "no readers" is `-EPIPE` (plus a
/// SIGPIPE to the caller) BEFORE the non-blocking test, and `SPLICE_F_NONBLOCK`
/// (`-EAGAIN`) comes BEFORE the signal check. # C: O(1) + park
pub fn opipe_prep(p: &PipeData, nonblock: bool) -> KResult<()> {
    loop {
        if p.readers.load(Ordering::Acquire) == 0 {
            #[cfg(target_os = "oxide-kernel")]
            sched::live::sigpend::send_signal_self(sched::signum::Signum::Sigpipe);
            return Err(VfsError::Epipe);
        }
        if space(p) != 0 { return Ok(()); }
        if nonblock { return Err(VfsError::Eagain); }
        #[cfg(target_os = "oxide-kernel")]
        if sched::live::deliverable_signals_self() != 0 { return Err(VfsError::Erestartsys); }
        #[cfg(target_os = "oxide-kernel")]
        {
            // SAFETY: running task on this CPU; preempt-off; park enqueues on
            // write_waiters before schedule, and a reader's drain wakes it.
            unsafe { p.write_waiters.park(); }
            // SAFETY: process ctx; runqueue installed; current Sleeping until a
            // reader drains the ring or the last reader closes.
            unsafe { sched::live::schedule::schedule(); }
        }
        #[cfg(not(target_os = "oxide-kernel"))]
        return Err(VfsError::Eagain);
    }
}

/// Wake every task blocked on `p`'s read side and notify pollers — run after
/// bytes land in an output pipe. # C: O(N_waiters)
pub fn wake_readers(p: &PipeData, inode: &vfs::Inode) {
    p.read_waiters.wake_all();
    if let Some(s) = inode.poll_subscribers() { s.notify(); }
}

/// Symmetric wake for the write side, after bytes leave an input pipe.
/// # C: O(N_waiters)
pub fn wake_writers(p: &PipeData, inode: &vfs::Inode) {
    p.write_waiters.wake_all();
    if let Some(s) = inode.poll_subscribers() { s.notify(); }
}
