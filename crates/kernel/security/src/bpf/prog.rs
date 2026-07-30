// `BPF_PROG_LOAD`, `BPF_PROG_ATTACH`/`BPF_PROG_DETACH`, `BPF_LINK_CREATE`.
// Ordering mirrors kernel/bpf/syscall.c `bpf_prog_load()`,
// `bpf_prog_attach()` and `link_create()`; every errno decision itself
// lives in `attr.rs` so it is hosted-testable.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use syscall::errno::Errno;
use vfs::InodeRef;

use super::attr::{self, Attr, Caps};
use super::uapi;
use super::user;
use super::{
    BpfLsmLinkInode, BpfProgInode, install_fd, make_bpf_lsm_link_inode,
    make_bpf_prog_inode, prog_by_id,
};

struct ClassicAttach<P, T> {
    prog: P,
    target: T,
    replace: Option<P>,
    mode: cgroup::BpfDeviceMode,
}

fn resolve_classic_attach<P, T>(
    flags: u32,
    relative_fd: u32,
    prog_fd: i32,
    target_fd: i32,
    replace_fd: i32,
    mut resolve_prog: impl FnMut(i32) -> Result<P, Errno>,
    resolve_target: impl FnOnce(i32) -> Result<T, Errno>,
) -> Result<ClassicAttach<P, T>, Errno> {
    let prog = resolve_prog(prog_fd)?;
    let target = resolve_target(target_fd)?;
    let replace_requested = flags & uapi::attach_flags::REPLACE != 0;
    let replace = if replace_requested && flags & uapi::attach_flags::ALLOW_MULTI != 0 {
        Some(resolve_prog(replace_fd)?)
    } else {
        None
    };
    let mode = match flags & !uapi::attach_flags::REPLACE {
        0 => cgroup::BpfDeviceMode::Single,
        uapi::attach_flags::ALLOW_OVERRIDE => cgroup::BpfDeviceMode::Override,
        uapi::attach_flags::ALLOW_MULTI => cgroup::BpfDeviceMode::Multi,
        _ => return Err(Errno::Einval),
    };
    if replace_requested && mode != cgroup::BpfDeviceMode::Multi || relative_fd != 0 {
        return Err(Errno::Einval);
    }
    Ok(ClassicAttach { prog, target, replace, mode })
}

fn resolve_query_target<T>(
    query: &attr::ProgQuery,
    resolve_target: impl FnOnce(i32) -> Result<T, Errno>,
) -> Result<T, Errno> {
    let target = resolve_target(query.target_fd as i32)?;
    if query.query_flags & uapi::query_flags::EFFECTIVE != 0
        && query.prog_attach_flags != 0 {
        return Err(Errno::Einval);
    }
    Ok(target)
}

/// `char license[128]` in `bpf_prog_load()`.
const LICENSE_MAX: usize = 128;

/// `bpf_prog_load()`. # C: O(insn_cnt)
pub(super) fn load(a: &Attr, caps: Caps) -> Result<i64, Errno> {
    let p = attr::prog_load_check(a, caps, attr::unpriv_bpf_disabled())?;
    let total = p.insn_cnt as usize * uapi::INSN_SIZE as usize;
    // Linux copies insns then the license *before* `find_prog_type()`,
    // so a bad pointer is EFAULT even for a prog type with no runner.
    let insns = user::read_vec(p.insns, total)?;
    read_license(p.license)?;
    if !attr::prog_type_supported(p.prog_type) { return Err(Errno::Einval); }
    verify(p.prog_type, &insns)?;
    let inode = make_bpf_prog_inode(p.prog_type, insns);
    install_fd(inode, "bpf-prog")
}

/// `strncpy_from_bpfptr(license, attr->license, sizeof(license) - 1) < 0`
/// is `-EFAULT` — a NULL or unmapped `attr.license` fails the load, so
/// the pointer is read one byte at a time up to the NUL. # C: O(len)
fn read_license(ptr: u64) -> Result<Vec<u8>, Errno> {
    let mut out: Vec<u8> = Vec::new();
    for i in 0..LICENSE_MAX as u64 - 1 {
        let mut b = [0u8; 1];
        user::read_bytes(ptr + i, &mut b)?;
        if b[0] == 0 { return Ok(out); }
        out.push(b[0]);
    }
    Ok(out)
}

/// `bpf_check()`.  Each advertised type has a matching runner and verifier.
///
/// The structural rejects all map onto Linux verifier paths returning
/// `-EINVAL`: `"jump out of range"`, `"last insn is not an exit or
/// jmp"`, `"R%d is invalid"`, `"unknown opcode %02x"`
/// (kernel/bpf/verifier.c). # C: O(insn_cnt)
fn verify(prog_type: u32, insns: &[u8]) -> Result<(), Errno> {
    let verdict = match prog_type {
        uapi::prog_type::SOCKET_FILTER => crate::bpf_verify::verify_socket_filter(insns),
        uapi::prog_type::CGROUP_DEVICE => crate::bpf_verify::verify_cgroup_device(insns),
        _ => return Err(Errno::Einval),
    };
    verdict.map_err(|_| Errno::Einval)
}

/// `bpf_prog_attach()` / `bpf_prog_detach()`. # C: O(descendants * programs)
pub(super) fn attach(a: &Attr, detach: bool) -> Result<i64, Errno> {
    use uapi::off::prog_attach as o;
    let ptype = attr::prog_attach_check(a)?;
    if ptype != uapi::prog_type::CGROUP_DEVICE {
        return Err(attr::prog_attach_verdict(ptype));
    }
    let target_fd = a.u32_at(o::TARGET_FD) as i32;
    let prog_fd = a.u32_at(o::ATTACH_BPF_FD) as i32;
    let expected_revision = a.u64_at(o::EXPECTED_REVISION);
    if detach {
        if a.u32_at(o::ATTACH_FLAGS) != 0 || a.u32_at(o::RELATIVE_FD) != 0 {
            return Err(Errno::Einval);
        }
        let target = cgroup_from_fd(target_fd)?;
        // Legacy cgroup detach converts an invalid program fd to a null
        // program. ALLOW_MULTI then reports EINVAL because program identity is
        // mandatory; single/override modes retain Linux's compatibility
        // behavior and detach their sole entry.
        let inode = prog_inode_from_fd(prog_fd).ok()
            .filter(|inode| prog_type_of(inode) == Ok(ptype));
        super::cgroup_device::detach(target.cgid(), inode.as_ref(), expected_revision)?;
    } else {
        let flags = a.u32_at(o::ATTACH_FLAGS);
        let resolved = resolve_classic_attach(
            flags,
            a.u32_at(o::RELATIVE_FD),
            prog_fd,
            target_fd,
            a.u32_at(o::REPLACE_BPF_FD) as i32,
            |fd| typed_prog_inode_from_fd(fd, ptype),
            cgroup_from_fd,
        )?;
        super::cgroup_device::attach(
            resolved.target.cgid(),
            resolved.prog,
            resolved.mode,
            resolved.replace.as_ref(),
            expected_revision,
        )?;
    }
    Ok(0)
}

/// `bpf_prog_query()` for the canonical cgroup-owned DEVICE arrays.
/// # C: O(program count)
pub(super) fn query(a: &Attr, uattr: u64, uattr_size: u32, caps: Caps) -> Result<i64, Errno> {
    use uapi::off::prog_query as o;
    let q = attr::prog_query_check(a, caps)?;
    let target = resolve_query_target(&q, cgroup_from_fd)?;
    let snapshot = cgroup::bpf::device_query(target.cgid())
        .map_err(super::cgroup_device::map_error)?;
    let effective = q.query_flags & uapi::query_flags::EFFECTIVE != 0;
    let programs = if effective { &snapshot.effective } else { &snapshot.direct };
    let total = programs.len() as u32;
    let attach_flags = if effective {
        0u32
    } else {
        match snapshot.mode {
            Some(cgroup::BpfDeviceMode::Single) | None => 0,
            Some(cgroup::BpfDeviceMode::Override) => uapi::attach_flags::ALLOW_OVERRIDE,
            Some(cgroup::BpfDeviceMode::Multi) => uapi::attach_flags::ALLOW_MULTI,
        }
    };
    user::write_bytes(uattr + o::ATTACH_FLAGS as u64, &attach_flags.to_ne_bytes())?;
    user::write_bytes(uattr + o::PROG_CNT as u64, &total.to_ne_bytes())?;
    if uattr_size as usize >= o::LAST_END {
        let revision = if effective { 0 } else { snapshot.revision };
        user::write_bytes(uattr + o::REVISION as u64, &revision.to_ne_bytes())?;
    }
    if q.prog_cnt == 0 || q.prog_ids == 0 || total == 0 { return Ok(0); }

    let count = q.prog_cnt.min(total) as usize;
    let mut ids = Vec::with_capacity(count * 4);
    for inode in programs.iter().take(count) {
        let id = inode.private::<BpfProgInode>().ok_or(Errno::Einval)?.id;
        ids.extend_from_slice(&id.to_ne_bytes());
    }
    user::write_bytes(q.prog_ids, &ids)?;
    if q.prog_attach_flags != 0 {
        let mut flags = Vec::with_capacity(count * 4);
        for _ in 0..count {
            flags.extend_from_slice(&attach_flags.to_ne_bytes());
        }
        user::write_bytes(q.prog_attach_flags, &flags)?;
    }
    if q.prog_cnt < total { Err(Errno::Enospc) } else { Ok(0) }
}

/// `bpf_prog_get_fd_by_id()`: recover a live queried program object.
/// # C: O(log programs)
pub(super) fn get_fd_by_id(a: &Attr, caps: Caps) -> Result<i64, Errno> {
    let id = attr::prog_get_fd_by_id_check(a, caps)?;
    let inode = prog_by_id(id).ok_or(Errno::Enoent)?;
    install_fd(inode, "bpf-prog")
}

/// `link_create()` for `BPF_LSM_MAC`. # C: O(1)
pub(super) fn link_create(a: &Attr) -> Result<i64, Errno> {
    let l = attr::link_create_check(a)?;
    let hook = crate::bpf_lsm::hook_from_target_btf_id(l.target_btf_id).ok_or(Errno::Eopnotsupp)?;
    let inode = prog_inode_from_fd(l.prog_fd as i32)?;
    if prog_type_of(&inode)? != uapi::prog_type::LSM { return Err(Errno::Einval); }
    let id = crate::bpf_lsm::register(hook);
    let link: InodeRef = make_bpf_lsm_link_inode(BpfLsmLinkInode { id, _hook: hook, _prog: inode });
    install_fd(link, "bpf-link")
}

fn prog_inode_from_fd(fd: i32) -> Result<InodeRef, Errno> {
    let cur = sched::current().ok_or(Errno::Ebadf)?;
    // SAFETY: running task on this CPU; preempt-off on the syscall path; sole reader of the fd_table slot.
    let fdt = unsafe { cur.fd_table_ref() }.ok_or(Errno::Ebadf)?.clone();
    let file = fdt.get(fd).map_err(|_| Errno::Ebadf)?;
    let inode = Arc::clone(file.inode());
    if inode.private::<BpfProgInode>().is_none() { return Err(Errno::Einval); }
    Ok(inode)
}

fn prog_type_of(inode: &InodeRef) -> Result<u32, Errno> {
    inode.private::<BpfProgInode>().map(|p| p.prog_type).ok_or(Errno::Einval)
}

fn typed_prog_inode_from_fd(fd: i32, ptype: u32) -> Result<InodeRef, Errno> {
    let inode = prog_inode_from_fd(fd)?;
    if prog_type_of(&inode)? != ptype { return Err(Errno::Einval); }
    Ok(inode)
}

fn cgroup_from_fd(fd: i32) -> Result<cgroup::bpf::DeviceTarget, Errno> {
    let cur = sched::current().ok_or(Errno::Ebadf)?;
    // SAFETY: running task on this CPU; preempt-off; sole reader of the fd-table slot.
    let fdt = unsafe { cur.fd_table_ref() }.ok_or(Errno::Ebadf)?;
    let file = fdt.get(fd).map_err(|_| Errno::Ebadf)?;
    let inode = file.inode();
    if inode.file_type() != vfs::FileType::Directory { return Err(Errno::Ebadf); }
    let cgid = cgroup::cgid_from_dir_inode(inode.ino(), inode.fsid()).ok_or(Errno::Ebadf)?;
    cgroup::bpf::device_target(cgid).map_err(super::cgroup_device::map_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use core::cell::RefCell;

    #[test]
    fn classic_attach_resolves_linux_fd_order_before_semantic_flags() {
        let events = RefCell::new(Vec::new());
        let flags = uapi::attach_flags::ALLOW_OVERRIDE
            | uapi::attach_flags::ALLOW_MULTI
            | uapi::attach_flags::REPLACE;
        let result = resolve_classic_attach(
            flags,
            0,
            11,
            12,
            13,
            |fd| {
                events.borrow_mut().push(fd);
                if fd == 13 { Err(Errno::Ebadf) } else { Ok(fd) }
            },
            |fd| {
                events.borrow_mut().push(fd);
                Ok(fd)
            },
        );
        assert!(matches!(result, Err(Errno::Ebadf)));
        assert_eq!(*events.borrow(), alloc::vec![11, 12, 13]);
    }

    #[test]
    fn classic_attach_bad_program_and_target_precede_invalid_mode() {
        let flags = uapi::attach_flags::ALLOW_OVERRIDE | uapi::attach_flags::ALLOW_MULTI;
        let bad_prog = resolve_classic_attach(
            flags, 0, 11, 12, 0,
            |_| Err::<i32, _>(Errno::Ebadf),
            |_| Ok::<i32, _>(12),
        );
        assert!(matches!(bad_prog, Err(Errno::Ebadf)));

        let bad_target = resolve_classic_attach(
            flags, 0, 11, 12, 0,
            |_| Ok::<i32, _>(11),
            |_| Err::<i32, _>(Errno::Enoent),
        );
        assert!(matches!(bad_target, Err(Errno::Enoent)));

        let invalid = resolve_classic_attach(
            flags, 0, 11, 12, 0,
            |_| Ok::<i32, _>(11),
            |_| Ok::<i32, _>(12),
        );
        assert!(matches!(invalid, Err(Errno::Einval)));
    }

    #[test]
    fn query_resolves_online_target_before_effective_pointer_constraint() {
        let query = attr::ProgQuery {
            target_fd: 12,
            query_flags: uapi::query_flags::EFFECTIVE,
            prog_ids: 0,
            prog_cnt: 0,
            prog_attach_flags: 0x1000,
        };
        let stale = resolve_query_target(
            &query,
            |_| Err::<i32, _>(Errno::Enoent),
        );
        assert!(matches!(stale, Err(Errno::Enoent)));
        let live = resolve_query_target(&query, |_| Ok::<i32, _>(12));
        assert!(matches!(live, Err(Errno::Einval)));
    }
}
