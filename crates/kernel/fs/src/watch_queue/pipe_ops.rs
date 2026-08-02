// What a notification pipe does instead of what an ordinary pipe does.
//
// A notification pipe is not a byte stream: userspace may not write into it,
// and a reader gets whole records. The byte ring behind the pipe stays unused;
// the records live in the queue, which is where the loss accounting and the
// filter also live.

use vfs::{KResult, VfsError};

use super::queue::WatchQueue;

/// Non-blocking record read. An empty queue is EAGAIN — not end-of-file: the
/// kernel is the only writer, and it has not stopped existing. # C: O(records)
pub fn read_nb(q: &WatchQueue, buf: &mut [u8]) -> KResult<usize> {
    if buf.is_empty() { return Ok(0); }
    let records = q.read(buf.len()).map_err(errno_to_vfs)?;
    if records.is_empty() { return Err(VfsError::Eagain); }
    buf[..records.len()].copy_from_slice(&records);
    Ok(records.len())
}

/// Poll mask for a notification pipe: readable when a record — or a loss the
/// reader has not been told about — is waiting. It is never writable, because
/// userspace cannot write to it at all. # C: O(1)
pub fn poll_mask(q: &WatchQueue) -> u32 {
    if q.readable() { vfs::POLL_IN } else { 0 }
}

/// Writing to a notification pipe is EXDEV: the descriptor is a delivery
/// endpoint, not a channel, and its records come from the kernel. Reported as
/// a cross-device error rather than EBADF/EINVAL so a program that mistakes
/// one pipe for another gets a distinctive answer. # C: O(1)
pub fn write_refused() -> VfsError { VfsError::Exdev }

fn errno_to_vfs(e: syscall::errno::Errno) -> VfsError {
    match e {
        syscall::errno::Errno::Enobufs => VfsError::Enobufs,
        _ => VfsError::Einval,
    }
}
