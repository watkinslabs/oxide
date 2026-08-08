// Default vectored-write engine shared by backends that override the scalar
// write only. Split out of the parent so the vtable file stays a trait
// declaration.

use crate::file::File;
use crate::types::KResult;

use super::FileOps;

/// `write_iter_file` only for selected record-oriented objects. # C: O(sum lens)
pub fn stream_write_iter_file<O: FileOps + ?Sized>(ops: &O, file: &File, off: u64,
    bufs: &[&[u8]], nonblock: bool) -> KResult<usize>
{
    stream_write_iter_with(off, bufs, |pos, buf| {
        if nonblock {
            ops.write_nonblock_file(file, pos, buf)
        } else {
            ops.write_file(file, pos, buf)
        }
    })
}

/// Shared scalar fallback for vectored stream writes. Each successful full
/// slice advances the file position; a short write or post-progress error ends
/// the operation. # C: O(sum lens)
pub fn stream_write_iter_with<F>(off: u64, bufs: &[&[u8]], mut write: F) -> KResult<usize>
where F: FnMut(u64, &[u8]) -> KResult<usize>
{
    let mut total = 0usize;
    for buf in bufs {
        if buf.is_empty() { continue; }
        match write(off + total as u64, buf) {
            Ok(0) => break,
            Ok(n) => { total += n; if n < buf.len() { break; } }
            Err(e) if total == 0 => return Err(e),
            Err(_) => break,
        }
    }
    Ok(total)
}
