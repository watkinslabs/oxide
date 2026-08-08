// The two file<->pipe transfer legs of `splice(2)`: file-to-pipe and
// pipe-to-file.
//
// Both move ONE batch per call and report the byte count; the syscall wrapper
// owns the "keep going until `len` or a stall" loop, separating the
// batch-transfer actor from the driving loop.

use alloc::vec;

use vfs::{File, KResult, VfsError};

use crate::pipe::{self, PipeData};

/// Staging window for one batch. Deliberately heap, not stack: a page-sized
/// array in a syscall frame is the shape that overflowed the 16 KiB kernel
/// stack into the adjacent heap block. One `PIPE_CAP` worth is also the most a
/// single pipe can ever accept.
const STAGE: usize = 4096;

/// File → pipe. `pos` is the read offset when
/// `use_pos`, otherwise the description's own cursor is used and advanced.
///
/// Returns the bytes moved; `Ok(0)` is EOF on the input file, which the caller
/// turns into a 0 return. The output pipe is made ready first
/// (space is awaited), so `EPIPE` (no readers, plus SIGPIPE), `EAGAIN`
/// (non-blocking, full) and `ERESTARTSYS` all originate there, before the
/// read from the input file happens.
/// # C: O(bytes)
pub fn file_to_pipe(in_file: &File, pos: &mut u64, use_pos: bool,
                    out: &PipeData, out_file: &File, len: usize, nonblock: bool)
    -> KResult<usize>
{
    if len == 0 { return Ok(0); }
    pipe::opipe_prep(out, nonblock)?;
    let want = len.min(pipe::space(out)).min(STAGE);
    if want == 0 { return Ok(0); }
    let mut buf = vec![0u8; want];
    let n = if use_pos { in_file.pread(&mut buf, *pos as i64)? } else { in_file.read(&mut buf)? };
    if n == 0 { return Ok(0); }
    let w = pipe::fill(out, &buf[..n]);
    if w > 0 {
        pipe::wake_readers(out, out_file.inode());
        // Only the bytes the pipe accepted are consumed from the file; the rest
        // are re-read next round, so a short push never drops data.
        if use_pos { *pos += w as u64; }
        else { in_file.set_pos(in_file.pos() - (n - w) as u64); }
    } else if !use_pos {
        in_file.set_pos(in_file.pos() - n as u64);
    }
    Ok(w)
}

/// Pipe → file (`do_splice_from`). `pos` is the write offset when `use_pos`,
/// otherwise the description's cursor is used and advanced.
///
/// The pipe bytes are PEEKED and only consumed by the count the file write
/// accepted, mirroring Linux's release-the-buffer-after-the-write ordering: a
/// short or failing write must not swallow queued data. `Ok(0)` means the input
/// pipe reached EOF (all writers closed). # C: O(bytes)
pub fn pipe_to_file(inp: &PipeData, in_file: &File, out_file: &File,
                    pos: &mut u64, use_pos: bool, len: usize, nonblock: bool)
    -> KResult<usize>
{
    if len == 0 { return Ok(0); }
    if !pipe::ipipe_prep(inp, nonblock)? { return Ok(0); } // EOF
    let want = len.min(pipe::queued(inp)).min(STAGE);
    if want == 0 { return Ok(0); }
    let mut buf = vec![0u8; want];
    let n = pipe::peek(inp, &mut buf);
    if n == 0 { return Ok(0); }
    let w = match if use_pos { out_file.pwrite(&buf[..n], *pos as i64) } else { out_file.write(&buf[..n]) } {
        Ok(w)  => w,
        Err(e) => return Err(e),
    };
    if w > 0 {
        pipe::advance(inp, w);
        pipe::wake_writers(inp, in_file.inode());
        if use_pos { *pos += w as u64; }
    }
    Ok(w)
}

/// Pipe → pipe: a MOVE, so the
/// source is consumed. Both rings are made ready first — the input for data
/// (EOF ⇒ `Ok(0)`), the output for space. # C: O(bytes)
pub fn pipe_to_pipe(inp: &PipeData, in_file: &File, out: &PipeData, out_file: &File,
                    len: usize, nonblock: bool) -> KResult<usize>
{
    if len == 0 { return Ok(0); }
    if !pipe::ipipe_prep(inp, nonblock)? { return Ok(0); } // EOF
    pipe::opipe_prep(out, nonblock)?;
    let n = pipe::link_pipe(inp, out, len, /*consume*/ true);
    if n > 0 {
        pipe::wake_readers(out, out_file.inode());
        pipe::wake_writers(inp, in_file.inode());
    }
    Ok(n)
}

/// Map a `VfsError` to the negative errno the syscall returns, collapsing
/// `ERESTARTSYS` the way the signal-restart layer expects. # C: O(1)
pub fn err(e: VfsError) -> i64 { -(e as i64) }
