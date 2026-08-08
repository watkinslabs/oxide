// `bpf(2)` command table. One arm per command; every arm's validation and
// errno decision lives in the module that owns that command's object.

use syscall::SyscallArgs;
use syscall::errno::Errno;

use super::attr::Caps;
use super::uapi::cmd;
use super::{attr, btf, map, prog, token, user};

/// Effective capability snapshot. `bpf_capable()` and friends fold
/// CAP_SYS_ADMIN in, which [`Caps`] models. # C: O(1)
pub(super) fn caps_now() -> Result<Caps, Errno> {
    let cur = sched::current().ok_or(Errno::Esrch)?;
    Ok(Caps {
        bpf:       cur.has_cap(sched::cap::BPF),
        sys_admin: cur.has_cap(sched::cap::SYS_ADMIN),
        net_admin: cur.has_cap(sched::cap::NET_ADMIN),
        perfmon:   cur.has_cap(sched::cap::PERFMON),
    })
}

/// Fetch the command attribute, honouring the five-argument log-attr form.
/// # C: O(sizeof(bpf_attr))
pub(super) fn object_attr(args: &SyscallArgs) -> Result<attr::Attr, Errno> {
    if args.a0 as u32 & cmd::COMMON_ATTRS != 0 {
        let _ = user::fetch_common_attr(args.a3, args.a4 as u32)?;
    }
    user::fetch_attr(args.a1, args.a2 as u32)
}

/// The command is declared `int`, so the upper half of the register is not
/// part of it. # C: per command
pub(super) fn dispatch(args: &SyscallArgs) -> Result<i64, Errno> {
    let mut c = args.a0 as u32;
    let a = user::fetch_attr(args.a1, args.a2 as u32)?;
    let common = if c & cmd::COMMON_ATTRS != 0 {
        let common = user::fetch_common_attr(args.a3, args.a4 as u32)?;
        c &= !cmd::COMMON_ATTRS;
        Some(common)
    } else { None };
    let caps = caps_now()?;
    match c {
        cmd::MAP_CREATE                 => map::create(&a, caps),
        cmd::MAP_LOOKUP_ELEM            => map::elem(&a, map::MapOp::Lookup),
        cmd::MAP_UPDATE_ELEM            => map::elem(&a, map::MapOp::Update),
        cmd::MAP_DELETE_ELEM            => map::elem(&a, map::MapOp::Delete),
        cmd::MAP_LOOKUP_AND_DELETE_ELEM => map::elem(&a, map::MapOp::LookupAndDelete),
        cmd::MAP_GET_NEXT_KEY           => map::get_next_key(&a),
        cmd::MAP_FREEZE                 => map::freeze(&a),
        cmd::MAP_GET_FD_BY_ID           => map::get_fd_by_id(&a, caps),
        cmd::MAP_GET_NEXT_ID            => map::get_next_id(&a, args.a1, caps),
        cmd::PROG_LOAD                  => prog::load(&a, caps),
        cmd::PROG_ATTACH                => prog::attach(&a, false, caps),
        cmd::PROG_DETACH                => prog::attach(&a, true, caps),
        cmd::PROG_QUERY                 => prog::query(&a, args.a1, args.a2 as u32, caps),
        cmd::PROG_GET_FD_BY_ID          => prog::get_fd_by_id(&a, caps),
        cmd::PROG_BIND_MAP              => prog::bind_map(&a),
        cmd::LINK_CREATE                => prog::link_create(&a, caps),
        cmd::BTF_LOAD                   => btf::load(&a, args.a1, args.a2 as u32, common, caps),
        cmd::BTF_GET_FD_BY_ID           => btf::get_fd_by_id(&a, caps),
        cmd::BTF_GET_NEXT_ID            => btf::get_next_id(&a, args.a1, caps),
        cmd::OBJ_GET_INFO_BY_FD         => btf::get_info_by_fd(&a, args.a1),
        cmd::TOKEN_CREATE               => token::create(&a),
        // The command table's own `default`, reached only after the attr
        // size protocol above has had its say.
        _ => Err(Errno::Einval),
    }
}
