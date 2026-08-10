// `BPF_TASK_FD_QUERY` — what one descriptor of another task is attached to,
// and the write-back protocol that reports it.
//
// The command describes exactly two kinds of descriptor, in this order:
// a bpf link holding a raw-tracepoint attachment, and a perf-event fd.
// Anything else — a map fd, a program fd, a link of any other kind, a
// plain file — is `-ENOTSUPP` (524), which is not `-EOPNOTSUPP` (95).
//
// A perf-event fd is described from the program attached to the event.
// An event with no attached program is `-ENOENT` and nothing is written
// back, which is what every perf fd in this kernel answers today: no path
// attaches a program to an event. See the perf-SET_BPF and
// tracepoint-registry rows in `scratch/known_issues.md`.

extern crate alloc;
use alloc::vec::Vec;

use syscall::errno::Errno;
use vfs::InodeRef;

use super::super::super::attr::Attr;
use super::super::super::uapi;
use super::super::super::user;
use super::super::objfd;
use super::super::super::PerfFdPredicate;

/// The three descriptor classes the query distinguishes. The
/// raw-tracepoint link is absent because no link of that kind can exist
/// yet: the tree has no tracepoint registry to attach one to.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum QueriedFd {
    /// A bpf link that is not a raw-tracepoint link — the reference's
    /// `goto out_not_supp` inside the link arm.
    OtherLink,
    /// A perf-event fd.
    PerfEvent,
    /// Neither, so neither arm claims it.
    Other,
}

/// `file->f_op == &bpf_link_fops` first, `perf_get_event()` second.
/// # C: O(1)
pub(crate) fn classify(inode: &InodeRef, is_perf: PerfFdPredicate) -> QueriedFd {
    if objfd::link_kind(inode).is_some() { return QueriedFd::OtherLink; }
    if is_perf(inode) { return QueriedFd::PerfEvent; }
    QueriedFd::Other
}

/// `bpf_get_perf_event_info()`. The description is read off the program
/// attached to the event; without one there is nothing to describe and
/// the query stops before writing any field. No `perf_event_open` fd in
/// this kernel carries an attached program, so this is every perf fd's
/// answer. # C: O(1)
fn perf_event_info() -> Result<(u32, u32, Vec<u8>, u64, u64), Errno> {
    Err(Errno::Enoent)
}

/// `bpf_copy_to_user()`: the name plus its terminator when the caller's
/// buffer holds both, otherwise a truncated, still-terminated name and
/// `-ENOSPC`. A faulting buffer aborts the whole write-back.
/// # C: O(min(ulen, len))
fn copy_name(ubuf: u64, name: &[u8], ulen: u32) -> Result<(), Errno> {
    let ulen = ulen as usize;
    if ulen >= name.len() + 1 {
        user::write_bytes(ubuf, name)?;
        return user::write_bytes(ubuf + name.len() as u64, &[0u8]);
    }
    user::write_bytes(ubuf, &name[..ulen - 1])?;
    user::write_bytes(ubuf + ulen as u64 - 1, &[0u8])?;
    Err(Errno::Enospc)
}

fn write_u32(uattr: u64, offset: usize, value: u32) -> Result<(), Errno> {
    let at = uattr.checked_add(offset as u64).ok_or(Errno::Efault)?;
    user::write_bytes(at, &value.to_ne_bytes())
}

fn write_u64(uattr: u64, offset: usize, value: u64) -> Result<(), Errno> {
    let at = uattr.checked_add(offset as u64).ok_or(Errno::Efault)?;
    user::write_bytes(at, &value.to_ne_bytes())
}

/// `bpf_task_fd_query_copy()`. `buf_len` always reports the attach-point
/// name's real length, so a caller that sized its buffer wrong learns how
/// big to make it. A short buffer still receives every scalar field and
/// a terminated prefix of the name, and reports `-ENOSPC`; a name of
/// length zero leaves the buffer holding just a terminator.
/// # C: O(min(buf_len, name length))
pub(crate) fn copy_out(
    a: &Attr,
    uattr: u64,
    prog_id: u32,
    fd_type: u32,
    name: &[u8],
    probe_offset: u64,
    probe_addr: u64,
) -> Result<i64, Errno> {
    use uapi::off::task_fd_query as o;
    write_u32(uattr, o::BUF_LEN, name.len() as u32)?;
    let ubuf = a.u64_at(o::BUF);
    let input_len = a.u32_at(o::BUF_LEN);
    let mut short = Ok(());
    if input_len != 0 && ubuf != 0 {
        if name.is_empty() {
            user::write_bytes(ubuf, &[0u8])?;
        } else if let Err(e) = copy_name(ubuf, name, input_len) {
            // A faulting buffer abandons the write-back; a short one does not.
            if e == Errno::Efault { return Err(e); }
            short = Err(e);
        }
    }
    write_u32(uattr, o::PROG_ID, prog_id)?;
    write_u32(uattr, o::FD_TYPE, fd_type)?;
    write_u64(uattr, o::PROBE_OFFSET, probe_offset)?;
    write_u64(uattr, o::PROBE_ADDR, probe_addr)?;
    short.map(|()| 0)
}

/// Describe one classified descriptor and report it. # C: O(name length)
pub(crate) fn describe(a: &Attr, uattr: u64, fd: QueriedFd) -> Result<i64, Errno> {
    match fd {
        QueriedFd::PerfEvent => {
            let (prog_id, fd_type, name, probe_offset, probe_addr) = perf_event_info()?;
            copy_out(a, uattr, prog_id, fd_type, &name, probe_offset, probe_addr)
        }
        QueriedFd::OtherLink | QueriedFd::Other => Err(Errno::Enotsupp),
    }
}

#[cfg(test)]
#[path = "query/tests.rs"]
mod tests;
