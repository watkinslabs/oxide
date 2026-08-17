// `IORING_OP_READV_FIXED` / `IORING_OP_WRITEV_FIXED` — a vectored transfer
// whose segments address a REGISTERED buffer.
//
// The segments are read out of the caller's memory the way any vector is, but
// what they name is not: each `(base, len)` pair is placed inside the
// registration named by `buf_index`, and a pair that falls outside it is
// `EFAULT` before a byte moves. So the bytes reach the frames pinned at
// registration time and nothing the process has done to its mappings since can
// redirect them — which is the whole reason to register a buffer, kept intact
// across a vector's several pieces.
//
// Short-transfer behaviour is a vector's: the run stops at the first segment
// that could not be filled, and the bytes already moved are the result. An
// error is reported only when no bytes moved at all, because a caller that
// received a count has already had part of its request honoured.

use alloc::sync::Arc;

use syscall::errno::Errno;

use crate::io_uring_abi::recvsend::fixed::window;
use crate::io_uring_abi::rw_vec::{prep_vec_fixed, seg_from_wire, IOVEC_BYTES};

use super::router::Op;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// The offset a segment run starts at. A negative explicit offset is `EINVAL`,
/// exactly as a positional read's is — only the sentinel meaning "use the
/// description's own position" may have the top bit set, and that arrives here
/// as `None` rather than as a number. # C: O(1)
fn start_pos(off: Option<u64>) -> Result<Option<i64>, i64> {
    match off {
        None => Ok(None),
        Some(v) if (v as i64) < 0 => Err(err(Errno::Einval)),
        Some(v) => Ok(Some(v as i64)),
    }
}

/// # C: O(total bytes)
pub fn vec_fixed(op: &Op) -> i64 {
    let v = match prep_vec_fixed(op.sqe) { Ok(v) => v, Err(e) => return err(e) };
    if let Err(e) = super::rw::attr_admission(op) { return e; }
    if let Err(e) = super::rw::polled_admission(op, false) { return e; }
    let file = match super::rw::file_of(op.fd) { Ok(f) => f, Err(e) => return e };
    let buf = match super::fdres::reg_buf(op.inode, v.buf_index as u32) { Ok(b) => b, Err(e) => return e };
    let mut pos = match start_pos(v.off) { Ok(p) => p, Err(e) => return e };

    let vec_bytes = (v.nr as u64) * IOVEC_BYTES;
    if !uaccess::access_ok(v.uvec, vec_bytes as usize) { return err(Errno::Efault); }

    let mut moved: u64 = 0;
    for i in 0..v.nr as u64 {
        let mut wire = [0u8; IOVEC_BYTES as usize];
        if uaccess::copy_from_user(&mut wire, v.uvec + i * IOVEC_BYTES).is_err() {
            return if moved > 0 { moved as i64 } else { err(Errno::Efault) };
        }
        let seg = seg_from_wire(&wire);
        if seg.len == 0 { continue; }
        if seg.len > u32::MAX as u64 { return err(Errno::Einval); }
        let w = match window(buf.base, buf.len, seg.base, seg.len as u32) {
            Ok(w) => w,
            Err(e) => return if moved > 0 { moved as i64 } else { err(e) },
        };
        let (n, failed) = run_window(&file, &buf, w.off, w.len, &mut pos, v.write);
        moved += n;
        if failed != 0 { return if moved > 0 { moved as i64 } else { failed }; }
        // Short: the description had no more to give, or would not take more.
        if n < w.len { break; }
    }
    moved as i64
}

/// Move one segment's worth of bytes through the pinned frames, advancing the
/// file position as it goes. Returns what moved and the failure that stopped
/// it, if any. # C: O(len)
fn run_window(file: &Arc<vfs::File>, buf: &Arc<crate::io_uring::pin::PinnedRange>,
              off: u64, len: u64, pos: &mut Option<i64>, write: bool) -> (u64, i64)
{
    let mut failed: i64 = 0;
    let walked = buf.for_each_chunk(off, len, |chunk| {
        // No offset means the description's own cursor, which the positional
        // calls do not touch: taking the stream path is what makes one entry
        // work on a pipe or a socket, where a position means nothing.
        let r = match (write, *pos) {
            (false, Some(p)) => file.pread(chunk, p),
            (true,  Some(p)) => file.pwrite(chunk, p),
            (false, None)    => file.read(chunk),
            (true,  None)    => file.write(chunk),
        };
        match r {
            Ok(0) => None,
            Ok(n) => { if let Some(p) = pos.as_mut() { *p += n as i64; } Some(n) }
            Err(e) => { failed = crate::namei_common::errno_from_vfs(e); None }
        }
    });
    match walked {
        Err(e) => (0, err(e)),
        Ok(n) => (n as u64, failed),
    }
}
