// `BPF_RAW_TRACEPOINT_OPEN` and `BPF_TASK_FD_QUERY`.
//
// Both commands reach for a tracepoint: the first attaches a program to
// one by name, the second reports which tracepoint or perf event a
// descriptor in another task stands for. This kernel has no tracepoint
// registry and no perf-event descriptors, so the name lookup finds
// nothing (`-ENOENT`) and the descriptor is never one of the two kinds
// the query can describe (`-ENOTSUPP`). Both are the reference's own
// answers for those inputs; the rungs above them are real. See the
// missing-tracepoint-registry and missing-perf-events rows in
// `scratch/known_issues.md`.

extern crate alloc;
use alloc::vec::Vec;

use syscall::errno::Errno;

use super::super::attr::{self, Attr, Caps};
use super::super::uapi;
use super::super::user;
use super::super::BpfProgInode;
use super::objfd;

/// `char buf[128]` — the tracepoint name buffer the attach path copies
/// the user string into.
const TP_NAME_MAX: usize = 128;

/// How a program type supplies its attach point.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum TpNameSource {
    /// The name comes from `attr.raw_tracepoint.name`.
    User,
    /// The attach point was fixed at load time by BTF id, so supplying a
    /// name is a caller error.
    LoadTime,
}

/// Which program types may be attached to a raw tracepoint, and where
/// each takes its attach point from. # C: O(1)
pub(crate) fn tp_name_source(prog_type: u32) -> Result<TpNameSource, Errno> {
    use uapi::prog_type as p;
    match prog_type {
        p::RAW_TRACEPOINT | p::RAW_TRACEPOINT_WRITABLE => Ok(TpNameSource::User),
        p::TRACING | p::EXT | p::LSM => Ok(TpNameSource::LoadTime),
        _ => Err(Errno::Einval),
    }
}

/// A load-time-attached program that also supplies a name is asking for
/// two different attach points. # C: O(1)
fn name_verdict(source: TpNameSource, name_ptr: u64) -> Result<(), Errno> {
    if source == TpNameSource::LoadTime && name_ptr != 0 { return Err(Errno::Einval); }
    Ok(())
}

/// `strncpy_from_user()` into the fixed name buffer; a name that does not
/// terminate inside it is truncated rather than refused. # C: O(len)
fn read_tp_name(ptr: u64) -> Result<Vec<u8>, Errno> {
    let mut out = Vec::new();
    for i in 0..TP_NAME_MAX as u64 - 1 {
        let mut byte = [0u8; 1];
        user::read_bytes(ptr.checked_add(i).ok_or(Errno::Efault)?, &mut byte)?;
        if byte[0] == 0 { break; }
        out.push(byte[0]);
    }
    Ok(out)
}

/// Resolve one tracepoint by name. This kernel registers none, so every
/// name is unknown. # C: O(registered tracepoints)
fn tracepoint_by_name(_name: &[u8]) -> Option<()> { None }

/// `bpf_raw_tracepoint_open()`. No capability of its own: the right to
/// attach was decided when the program was loaded. # C: O(name length)
pub(in super::super) fn raw_tracepoint_open(a: &Attr) -> Result<i64, Errno> {
    use uapi::off::raw_tracepoint as o;
    attr::check_attr(a, o::LAST_END)?;
    let inode = objfd::prog_from_fd(a.u32_at(o::PROG_FD))?;
    let prog = inode.private::<BpfProgInode>().ok_or(Errno::Einval)?;
    let source = tp_name_source(prog.prog_type)?;
    let name_ptr = a.u64_at(o::NAME);
    name_verdict(source, name_ptr)?;
    let name = match source {
        TpNameSource::User => read_tp_name(name_ptr)?,
        TpNameSource::LoadTime => Vec::new(),
    };
    tracepoint_by_name(&name).ok_or(Errno::Enoent)?;
    Err(Errno::Enoent)
}

/// The description of one queried descriptor. The command can describe
/// exactly two kinds — a link holding a raw-tracepoint attachment, and a
/// perf-event fd — and this kernel mints neither, so every descriptor
/// that survives the lookup is `-ENOTSUPP` (524). That is not
/// `-EOPNOTSUPP` (95), which neighbouring link commands return for their
/// own shape of refusal. # C: O(1)
fn describe_verdict() -> Result<i64, Errno> { Err(Errno::Enotsupp) }

/// Resolve one descriptor of another task. `-ENOENT` when the pid names
/// no task, `-EBADF` when that task has no such descriptor. # C: O(1)
fn task_fd(pid: u32, fd: u32) -> Result<vfs::InodeRef, Errno> {
    let task = sched::registry::lookup(pid).ok_or(Errno::Enoent)?;
    // SAFETY: sched::registry::lookup pins the task in an Arc that outlives this borrow of its fd table.
    let fdt = unsafe { task.fd_table_ref() }.ok_or(Errno::Ebadf)?.clone();
    let file = fdt.get(fd as i32).map_err(|_| Errno::Ebadf)?;
    Ok(alloc::sync::Arc::clone(file.inode()))
}

/// `bpf_task_fd_query()`. # C: O(1)
pub(in super::super) fn task_fd_query(a: &Attr, caps: Caps) -> Result<i64, Errno> {
    use uapi::off::task_fd_query as o;
    attr::check_attr(a, o::LAST_END)?;
    if !caps.sys_admin { return Err(Errno::Eperm); }
    if a.u32_at(o::FLAGS) != 0 { return Err(Errno::Einval); }
    let _inode = task_fd(a.u32_at(o::PID), a.u32_at(o::FD))?;
    describe_verdict()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admin() -> Caps { Caps { bpf: false, sys_admin: true, net_admin: false, perfmon: false } }

    #[test]
    fn check_attr_boundaries_are_the_uapi_offsetofends() {
        assert_eq!(uapi::off::raw_tracepoint::LAST_END, 24);
        assert_eq!(uapi::off::raw_tracepoint::PROG_FD, 8);
        assert_eq!(uapi::off::raw_tracepoint::COOKIE, 16);
        assert_eq!(uapi::off::task_fd_query::LAST_END, 48);
        assert_eq!(uapi::off::task_fd_query::PROBE_ADDR, 40);
    }

    /// The 12..16 gap between `prog_fd` and the 8-aligned `cookie` is
    /// padding inside the checked struct, so a byte there is accepted;
    /// a byte past `cookie` is not.
    #[test]
    fn the_padding_before_cookie_is_inside_the_command_not_past_it() {
        let mut a = Attr::zeroed();
        let fd = uapi::off::raw_tracepoint::PROG_FD;
        a.bytes[fd..fd + 4].copy_from_slice(&u32::MAX.to_ne_bytes());
        a.bytes[12] = 1;
        assert_eq!(raw_tracepoint_open(&a), Err(Errno::Ebadf));
        a.bytes[uapi::off::raw_tracepoint::LAST_END] = 1;
        assert_eq!(raw_tracepoint_open(&a), Err(Errno::Einval));
    }

    #[test]
    fn only_tracepoint_and_load_time_attached_program_types_may_open_one() {
        use uapi::prog_type as p;
        assert_eq!(tp_name_source(p::RAW_TRACEPOINT), Ok(TpNameSource::User));
        assert_eq!(tp_name_source(p::RAW_TRACEPOINT_WRITABLE), Ok(TpNameSource::User));
        for load_time in [p::TRACING, p::EXT, p::LSM] {
            assert_eq!(tp_name_source(load_time), Ok(TpNameSource::LoadTime));
        }
        for other in [p::SOCKET_FILTER, p::CGROUP_SKB, p::XDP, p::UNSPEC, p::STRUCT_OPS] {
            assert_eq!(tp_name_source(other), Err(Errno::Einval));
        }
    }

    #[test]
    fn a_load_time_attached_program_may_not_also_name_a_tracepoint() {
        assert_eq!(name_verdict(TpNameSource::LoadTime, 0), Ok(()));
        assert_eq!(name_verdict(TpNameSource::LoadTime, 0x1000), Err(Errno::Einval));
        assert_eq!(name_verdict(TpNameSource::User, 0), Ok(()));
        assert_eq!(name_verdict(TpNameSource::User, 0x1000), Ok(()));
    }

    #[test]
    fn no_tracepoint_name_resolves_in_this_kernel() {
        assert_eq!(tracepoint_by_name(b"sys_enter"), None);
        assert_eq!(tracepoint_by_name(b""), None);
    }

    /// The capability is checked before the `flags` field and before the
    /// pid, so an unprivileged caller with a bad flag sees EPERM.
    #[test]
    fn task_fd_query_checks_cap_sys_admin_before_flags_and_pid() {
        let mut a = Attr::zeroed();
        let f = uapi::off::task_fd_query::FLAGS;
        a.bytes[f..f + 4].copy_from_slice(&1u32.to_ne_bytes());
        assert_eq!(task_fd_query(&a, Caps::default()), Err(Errno::Eperm));
        assert_eq!(task_fd_query(&a, admin()), Err(Errno::Einval));
    }

    /// The zero-tail check precedes even the capability.
    #[test]
    fn task_fd_query_checks_the_attr_tail_before_the_capability() {
        let mut a = Attr::zeroed();
        a.bytes[uapi::off::task_fd_query::LAST_END] = 1;
        assert_eq!(task_fd_query(&a, Caps::default()), Err(Errno::Einval));
    }

    /// `ENOTSUPP` is 524 and distinct from `EOPNOTSUPP` (95) — the two
    /// appear on neighbouring commands and are not interchangeable.
    #[test]
    fn an_undescribable_descriptor_is_enotsupp_not_eopnotsupp() {
        assert_eq!(describe_verdict(), Err(Errno::Enotsupp));
        assert_eq!(Errno::Enotsupp.as_i32(), 524);
        assert_eq!(Errno::Eopnotsupp.as_i32(), 95);
    }
}
