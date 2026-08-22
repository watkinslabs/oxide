// `BPF_TASK_FD_QUERY` — what one descriptor of another task is attached to,
// and the write-back protocol that reports it.
//
// The command describes exactly two kinds of descriptor, in this order:
// a bpf link holding a raw-tracepoint attachment, and a perf-event fd.
// Anything else — a map fd, a program fd, a link of any other kind, a
// plain file — is `-ENOTSUPP` (524), which is not `-EOPNOTSUPP` (95).
//
// A raw-tracepoint link is described from the program and event name retained
// by that link; there is no query-side registry or copied attachment state.
// A perf-event fd is described from the program attached to the event.
// An event with no attached program is `-ENOENT` and nothing is written
// back. A program of the perf-event type is deliberately not described:
// the reference reports `-EOPNOTSUPP` (95) for one, because the description
// it would produce names a trace attach point and a perf-event program has
// none. The only perf PMU this kernel currently exposes is non-tracing and
// admits only that program type; tracing perf events remain a separate PMU
// surface rather than a synthetic description here.

extern crate alloc;
use alloc::vec::Vec;

use syscall::errno::Errno;
use vfs::InodeRef;

use super::super::super::attr::Attr;
use super::super::super::uapi;
use super::super::super::user;
use super::super::objfd;
use super::super::super::{
    raw_tracepoint_link_info, PerfHooks, ProgFacts, RawTracepointLinkInfo,
    BPF_PROG_TYPE_PERF_EVENT,
};

/// Descriptor classes in the reference's decision order.
pub(crate) enum QueriedFd {
    /// A raw-tracepoint link and its canonical retained attachment.
    RawTracepoint(RawTracepointLinkInfo),
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
pub(crate) fn classify(inode: &InodeRef, perf: PerfHooks) -> QueriedFd {
    if let Some(info) = raw_tracepoint_link_info(inode) {
        return QueriedFd::RawTracepoint(info);
    }
    if objfd::link_kind(inode).is_some() { return QueriedFd::OtherLink; }
    if (perf.is_perf)(inode) { return QueriedFd::PerfEvent; }
    QueriedFd::Other
}

/// `bpf_get_perf_event_info()`. The description is read off the program
/// attached to the event; without one there is nothing to describe and the
/// query stops before writing any field.
///
/// A perf-event program is refused outright. Anything else would require a
/// tracing perf event and its trace-event record; the current perf owner
/// exposes neither, so it is the same `-EOPNOTSUPP` the reference gives for
/// an unsupported probe kind. # C: O(1)
fn perf_event_info(prog: Option<ProgFacts>) -> Result<(u32, u32, Vec<u8>, u64, u64), Errno> {
    let prog = prog.ok_or(Errno::Enoent)?;
    if prog.prog_type == BPF_PROG_TYPE_PERF_EVENT { return Err(Errno::Eopnotsupp); }
    Err(Errno::Eopnotsupp)
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

/// Describe one classified descriptor and report it. `prog` is the perf
/// event's attached program, already resolved by the caller — only the perf
/// arm has one. # C: O(name length)
pub(crate) fn describe(a: &Attr, uattr: u64, fd: QueriedFd, prog: Option<ProgFacts>)
    -> Result<i64, Errno>
{
    match fd {
        QueriedFd::RawTracepoint(info) => {
            let prog = super::super::super::prog_facts(&info.prog).ok_or(Errno::Enotsupp)?;
            copy_out(a, uattr, prog.id, uapi::fd_type::RAW_TRACEPOINT,
                     info.name.as_bytes(), 0, 0)
        }
        QueriedFd::PerfEvent => {
            let (prog_id, fd_type, name, probe_offset, probe_addr) = perf_event_info(prog)?;
            copy_out(a, uattr, prog_id, fd_type, &name, probe_offset, probe_addr)
        }
        QueriedFd::OtherLink | QueriedFd::Other => Err(Errno::Enotsupp),
    }
}

#[cfg(test)]
#[path = "query/tests.rs"]
mod tests;
