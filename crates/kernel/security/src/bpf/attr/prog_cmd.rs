// Per-command validation for the program, attach, query and link commands.

use syscall::errno::Errno;

use super::super::uapi;
use super::{Attr, Caps, check_attr};
use super::caps::{is_net_admin_prog_type, is_perfmon_prog_type};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ProgLoad {
    pub prog_type: u32,
    pub insn_cnt: u32,
    pub insns: u64,
    pub license: u64,
    pub expected_attach_type: u32,
    pub attach_btf_id: u32,
    /// The one slot naming either a target program or the type-information
    /// object holding `attach_btf_id`. Which of the two it is depends on
    /// what the descriptor turns out to hold, so the raw value is carried
    /// and judged by [`attach_target_object`].
    pub attach_btf_obj_fd: u32,
}

/// What a nonzero attach-target descriptor turned out to hold.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AttachTarget {
    /// The request named no target descriptor. A nonzero `attach_btf_id`
    /// is then resolved against the kernel's own type information.
    None,
    /// The descriptor holds a loaded program to attach to.
    DstProg,
    /// The descriptor holds the kernel's own type information.
    KernelBtf,
}

/// `bpf_prog_load()`'s pre-copy ladder, in Linux's order:
/// `CHECK_ATTR` → `prog_flags` mask → `unprivileged_bpf_disabled` EPERM
/// → `insn_cnt` bounds (**E2BIG**, not EINVAL) → the "only SOCKET_FILTER
/// and CGROUP_SKB are loadable unprivileged" EPERM → CAP_NET_ADMIN
/// prog types → CAP_PERFMON prog types.
///
/// `find_prog_type()` deliberately is *not* here: Linux runs it after
/// copying insns and license, so a bad `insns` pointer is EFAULT even
/// for a prog type the kernel does not implement.
/// # C: O(ATTR_SIZE)
pub fn prog_load_check(a: &Attr, caps: Caps, unpriv_disabled: bool) -> Result<ProgLoad, Errno> {
    use uapi::off::prog_load as o;
    check_attr(a, o::LAST_END)?;
    let flags = a.u32_at(o::PROG_FLAGS);
    if flags & !uapi::prog_flags::LOAD_MASK != 0 { return Err(Errno::Einval); }
    let bpf_cap = caps.bpf_capable();
    if unpriv_disabled && !bpf_cap { return Err(Errno::Eperm); }
    let p = ProgLoad {
        prog_type: a.u32_at(o::PROG_TYPE), insn_cnt: a.u32_at(o::INSN_CNT),
        insns: a.u64_at(o::INSNS), license: a.u64_at(o::LICENSE),
        expected_attach_type: a.u32_at(o::EXPECTED_ATTACH_TYPE),
        attach_btf_id: a.u32_at(o::ATTACH_BTF_ID),
        attach_btf_obj_fd: a.u32_at(o::ATTACH_BTF_OBJ_FD),
    };
    let ceiling = if bpf_cap { uapi::COMPLEXITY_LIMIT_INSNS } else { uapi::MAXINSNS };
    if p.insn_cnt == 0 || p.insn_cnt > ceiling { return Err(Errno::E2big); }
    if p.prog_type != uapi::prog_type::SOCKET_FILTER
        && p.prog_type != uapi::prog_type::CGROUP_SKB && !bpf_cap { return Err(Errno::Eperm); }
    if is_net_admin_prog_type(p.prog_type) && !caps.net_admin_capable() { return Err(Errno::Eperm); }
    if is_perfmon_prog_type(p.prog_type) && !caps.perfmon_capable() { return Err(Errno::Eperm); }
    Ok(p)
}

/// `bpf_prog_load_check_attach()`: the attach-target block first, then the
/// per-prog-type expected-attach-type switch.
///
/// A nonzero attach target must name a type some object could declare, and
/// only the program types whose contract is fixed by an attach target may
/// name one at all. A resolved type-information object is meaningless
/// without a type id to read from it and cannot be combined with a target
/// program; a target program is only a target for the two program types
/// that run in another program's place.
/// # C: O(1)
pub fn prog_load_check_attach(
    prog_type: u32,
    attach_type: u32,
    attach_btf_id: u32,
    target: AttachTarget,
) -> Result<(), Errno> {
    use uapi::prog_type as p;
    let dst_prog = target == AttachTarget::DstProg;
    // A type id resolved against the kernel's own type information is the
    // no-descriptor case: the object is always available here.
    let attach_btf = target == AttachTarget::KernelBtf
        || target == AttachTarget::None && attach_btf_id != 0;
    if attach_btf_id != 0 {
        if attach_btf_id > super::super::btf::MAX_TYPE_ID { return Err(Errno::Einval); }
        if !attach_btf && !dst_prog { return Err(Errno::Einval); }
        if !matches!(prog_type, p::TRACING | p::LSM | p::STRUCT_OPS | p::EXT) {
            return Err(Errno::Einval);
        }
    }
    if attach_btf && (attach_btf_id == 0 || dst_prog) { return Err(Errno::Einval); }
    if dst_prog && !matches!(prog_type, p::TRACING | p::EXT) { return Err(Errno::Einval); }
    expected_attach_type_check(prog_type, attach_type)
}

/// What the attach-target descriptor was found to hold.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TargetFd {
    /// A loaded program.
    Prog,
    /// Type information the kernel published about itself.
    KernelBtfObject,
    /// Type information a loader supplied.
    UserBtfObject,
    /// Anything else, including a descriptor that is not open.
    Other,
}

/// Judge one nonzero attach-target descriptor. A loaded program is a target
/// program. Type information is a target only when it is the kernel's own:
/// attaching through a loader-supplied object is refused as unsupported
/// (`ENOTSUPP`), which is a different answer from the `EINVAL` a descriptor
/// holding neither gets. # C: O(1)
pub fn attach_target_object(found: TargetFd) -> Result<AttachTarget, Errno> {
    match found {
        TargetFd::Prog => Ok(AttachTarget::DstProg),
        TargetFd::KernelBtfObject => Ok(AttachTarget::KernelBtf),
        TargetFd::UserBtfObject => Err(Errno::Enotsupp),
        TargetFd::Other => Err(Errno::Einval),
    }
}

/// The expected-attach-type switch of `bpf_prog_load_check_attach()`.
/// # C: O(1)
pub fn expected_attach_type_check(prog_type: u32, attach_type: u32) -> Result<(), Errno> {
    use uapi::attach_type as a;
    use uapi::prog_type as p;
    let valid = match prog_type {
        p::CGROUP_SKB => matches!(attach_type, a::CGROUP_INET_INGRESS | a::CGROUP_INET_EGRESS),
        p::CGROUP_SOCK_ADDR => matches!(attach_type,
            a::CGROUP_INET4_BIND | a::CGROUP_INET6_BIND
                | a::CGROUP_INET4_CONNECT | a::CGROUP_INET6_CONNECT),
        _ => true,
    };
    if valid { Ok(()) } else { Err(Errno::Einval) }
}

// ------------------------------------------------------------ PROG_ATTACH

/// Maps an attach type to the prog type it is valid for. Returns
/// `BPF_PROG_TYPE_UNSPEC` for an attach type with no mapping, which the
/// PROG_ATTACH path turns into `-EINVAL`. # C: O(1)
pub fn attach_type_to_prog_type(attach_type: u32) -> u32 {
    use uapi::attach_type as at;
    use uapi::prog_type as p;
    match attach_type {
        at::CGROUP_INET_INGRESS | at::CGROUP_INET_EGRESS => p::CGROUP_SKB,
        at::CGROUP_INET4_BIND | at::CGROUP_INET6_BIND
            | at::CGROUP_INET4_CONNECT | at::CGROUP_INET6_CONNECT => p::CGROUP_SOCK_ADDR,
        at::CGROUP_DEVICE => p::CGROUP_DEVICE,
        at::LSM_MAC => p::LSM,
        at::TRACE_ITER => p::TRACING,
        _ => p::UNSPEC,
    }
}

/// `bpf_prog_attach()` / `bpf_prog_detach()`.
///
/// Linux resolves the attach type, then hands the request to a
/// per-subsystem attacher. Implemented cgroup types reach the hierarchy-owned
/// attachment engine; other mapped types retain their unavailable verdict.
///
/// Returns the resolved prog type so the caller can run Linux's
/// `bpf_prog_get_type(attr->attach_bpf_fd, ptype)` step — a bad fd is
/// EBADF, which precedes the attacher's EINVAL.
/// # C: O(ATTR_SIZE)
pub fn prog_attach_check(a: &Attr) -> Result<u32, Errno> {
    use uapi::off::prog_attach as o;
    check_attr(a, o::LAST_END)?;
    let ptype = attach_type_to_prog_type(a.u32_at(o::ATTACH_TYPE));
    if ptype == uapi::prog_type::UNSPEC { return Err(Errno::Einval); }
    // `bpf_mprog_supported()` is false and `is_cgroup_prog_type()` true
    // for every type reachable here, so `attach_flags` outside
    // BPF_F_ATTACH_MASK_BASE|MPROG is EINVAL.
    if a.u32_at(o::ATTACH_FLAGS) & !uapi::attach_flags::CGROUP_MASK != 0 {
        return Err(Errno::Einval);
    }
    Ok(ptype)
}

/// Verdict for attach types that have no matching runtime engine. Linux
/// dispatches to a per-subsystem attacher (`cgroup_bpf_prog_attach`,
/// `sock_map_get_from_fd`, `tcx_prog_attach`, …); an unavailable subsystem
/// returns the same `-EINVAL` as its `CONFIG_*=n` stub. # C: O(1)
pub fn prog_attach_verdict(_ptype: u32) -> Errno { Errno::Einval }

// ------------------------------------------------------------- PROG_QUERY

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ProgQuery {
    pub target_fd: u32,
    pub attach_type: u32,
    pub query_flags: u32,
    pub prog_ids: u64,
    pub prog_cnt: u32,
    pub prog_attach_flags: u64,
}

/// `bpf_prog_query()`: CAP_NET_ADMIN precedes CHECK_ATTR, then query flags and
/// attach-type dispatch. # C: O(ATTR_SIZE)
pub fn prog_query_check(a: &Attr, caps: Caps) -> Result<ProgQuery, Errno> {
    use uapi::off::prog_query as o;
    if !caps.net_admin_capable() { return Err(Errno::Eperm); }
    check_attr(a, o::LAST_END)?;
    let query_flags = a.u32_at(o::QUERY_FLAGS);
    if query_flags & !uapi::query_flags::EFFECTIVE != 0 { return Err(Errno::Einval); }
    let attach_type = a.u32_at(o::ATTACH_TYPE);
    if !matches!(attach_type,
        uapi::attach_type::CGROUP_DEVICE
            | uapi::attach_type::CGROUP_INET_INGRESS
            | uapi::attach_type::CGROUP_INET_EGRESS
            | uapi::attach_type::CGROUP_INET4_BIND
            | uapi::attach_type::CGROUP_INET6_BIND
            | uapi::attach_type::CGROUP_INET4_CONNECT
            | uapi::attach_type::CGROUP_INET6_CONNECT) {
        return Err(Errno::Einval);
    }
    let prog_attach_flags = a.u64_at(o::PROG_ATTACH_FLAGS);
    Ok(ProgQuery {
        target_fd: a.u32_at(o::TARGET_FD),
        attach_type,
        query_flags,
        prog_ids: a.u64_at(o::PROG_IDS),
        prog_cnt: a.u32_at(o::PROG_CNT),
        prog_attach_flags,
    })
}

/// `bpf_prog_get_fd_by_id()`: CHECK_ATTR precedes CAP_SYS_ADMIN.
/// # C: O(ATTR_SIZE)
pub fn prog_get_fd_by_id_check(a: &Attr, caps: Caps) -> Result<u32, Errno> {
    use uapi::off::prog_get_fd_by_id as o;
    check_attr(a, o::LAST_END)?;
    if !caps.sys_admin { return Err(Errno::Eperm); }
    Ok(a.u32_at(o::PROG_ID))
}

// ---------------------------------------------------------- PROG_BIND_MAP

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ProgBindMap { pub prog_fd: u32, pub map_fd: u32 }

/// Validate and decode one program-map lifetime binding. # C: O(ATTR_SIZE)
pub fn prog_bind_map_check(a: &Attr) -> Result<ProgBindMap, Errno> {
    use uapi::off::prog_bind_map as o;
    check_attr(a, o::LAST_END)?;
    if a.u32_at(o::FLAGS) != 0 { return Err(Errno::Einval); }
    Ok(ProgBindMap { prog_fd: a.u32_at(o::PROG_FD), map_fd: a.u32_at(o::MAP_FD) })
}

// ------------------------------------------------------------ LINK_CREATE

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct LinkCreate {
    pub prog_fd: u32, pub target_fd: u32, pub attach_type: u32, pub flags: u32,
    pub target_btf_id: u32, pub relative_fd: u32, pub expected_revision: u64,
    pub iter_info: u64, pub iter_info_len: u32,
}

/// `bpf_iter_link_attach()`'s first gate: the per-link information pointer
/// and its length are supplied together or not at all. # C: O(1)
pub fn iter_info_check(iter_info: u64, iter_info_len: u32) -> Result<(), Errno> {
    if (iter_info == 0) != (iter_info_len == 0) { return Err(Errno::Einval); }
    Ok(())
}

/// `link_create()` first-stage `CHECK_ATTR` and union decode. Program lookup
/// and program-type dispatch follow this stage on Linux. # C: O(ATTR_SIZE)
pub fn link_create_check(a: &Attr) -> Result<LinkCreate, Errno> {
    use uapi::off::link_create as o;
    check_attr(a, o::LAST_END)?;
    Ok(LinkCreate {
        prog_fd: a.u32_at(o::PROG_FD), target_fd: a.u32_at(o::TARGET_FD),
        attach_type: a.u32_at(o::ATTACH_TYPE), flags: a.u32_at(o::FLAGS),
        target_btf_id: a.u32_at(o::TARGET_BTF_ID),
        relative_fd: a.u32_at(o::CGROUP_RELATIVE_FD),
        expected_revision: a.u64_at(o::CGROUP_EXPECTED_REVISION),
        iter_info: a.u64_at(o::ITER_INFO), iter_info_len: a.u32_at(o::ITER_INFO_LEN),
    })
}

/// `cgroup_bpf_link_attach()` flag gate, before target-fd lookup. # C: O(1)
pub fn cgroup_link_flags_check(flags: u32) -> Result<(), Errno> {
    if flags & !uapi::attach_flags::CGROUP_LINK_MASK != 0 { Err(Errno::Einval) }
    else { Ok(()) }
}
