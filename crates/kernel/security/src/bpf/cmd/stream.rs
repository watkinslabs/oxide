// `BPF_PROG_STREAM_READ_BY_FD` — drain one of a program's output streams.
//
// A loaded program owns two ring buffers that its runtime writes
// diagnostics into; this command copies out whatever is queued and
// returns the byte count, 0 when the stream is empty. This kernel's
// program objects carry no such buffers, so the streams are permanently
// empty and every well-formed request reads 0 bytes. That is the
// reference's own answer for an empty stream, not a substitute for one —
// but it means the diagnostics a program would emit are not collected.
// See the missing-program-streams row in `scratch/known_issues.md`.

use syscall::errno::Errno;

use super::super::attr::{self, Attr};
use super::super::uapi;
use super::super::user;
use super::objfd;

/// Streams a program can be asked to drain. An id outside the set is a
/// caller error. # C: O(1)
pub(crate) mod stream_id {
    pub const STDOUT: u32 = 1;
    pub const STDERR: u32 = 2;
}

/// An id naming no stream is `-ENOENT`, not `-EINVAL`: the command's
/// refusal is "there is no such stream on this program", the same answer
/// a program that had no such stream would give. # C: O(1)
fn stream_id_verdict(stream_id: u32) -> Result<(), Errno> {
    match stream_id {
        stream_id::STDOUT | stream_id::STDERR => Ok(()),
        _ => Err(Errno::Enoent),
    }
}

/// Bytes available in one of a program's streams. No program object in
/// this kernel carries stream buffers, so every stream is empty.
/// # C: O(1)
fn drain(_prog: &vfs::InodeRef, _stream_id: u32, _buf: u64, _len: u32) -> Result<i64, Errno> {
    Ok(0)
}

/// `prog_stream_read()`. # C: O(bytes copied)
pub(in super::super) fn read(a: &Attr) -> Result<i64, Errno> {
    use uapi::off::prog_stream_read as o;
    attr::check_attr(a, o::LAST_END)?;
    let prog = objfd::prog_from_fd(a.u32_at(o::PROG_FD))?;
    let stream_id = a.u32_at(o::STREAM_ID);
    stream_id_verdict(stream_id)?;
    let buf = a.u64_at(o::STREAM_BUF);
    let len = a.u32_at(o::STREAM_BUF_LEN);
    if len != 0 { user::range_ok(buf, len as usize)?; }
    drain(&prog, stream_id, buf, len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_attr_boundary_is_offsetofend_prog_stream_read_prog_fd() {
        assert_eq!(uapi::off::prog_stream_read::LAST_END, 20);
        assert_eq!(uapi::off::prog_stream_read::PROG_FD, 16);
        let mut a = Attr::zeroed();
        a.bytes[uapi::off::prog_stream_read::LAST_END] = 1;
        assert_eq!(read(&a), Err(Errno::Einval));
    }

    /// The zero-tail check precedes the descriptor lookup, so a malformed
    /// attr naming a closed fd is EINVAL rather than EBADF.
    #[test]
    fn the_attr_tail_is_checked_before_the_program_descriptor() {
        let mut a = Attr::zeroed();
        let fd = uapi::off::prog_stream_read::PROG_FD;
        a.bytes[fd..fd + 4].copy_from_slice(&u32::MAX.to_ne_bytes());
        assert_eq!(read(&a), Err(Errno::Ebadf));
        a.bytes[uapi::off::prog_stream_read::LAST_END] = 1;
        assert_eq!(read(&a), Err(Errno::Einval));
    }

    #[test]
    fn only_the_two_named_streams_can_be_drained() {
        assert_eq!(stream_id_verdict(stream_id::STDOUT), Ok(()));
        assert_eq!(stream_id_verdict(stream_id::STDERR), Ok(()));
        for other in [0u32, 3, u32::MAX] {
            assert_eq!(stream_id_verdict(other), Err(Errno::Enoent));
        }
    }
}
