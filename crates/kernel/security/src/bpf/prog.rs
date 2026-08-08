// `BPF_PROG_LOAD`, `BPF_PROG_ATTACH`/`BPF_PROG_DETACH`, `BPF_LINK_CREATE`.
// Validation ordering matches the load/attach/link-create command handlers;
// every errno decision itself lives in `attr.rs` so it is hosted-testable.

extern crate alloc;
use alloc::vec::Vec;

use syscall::errno::Errno;
use vfs::InodeRef;

use super::attr::{self, Attr, Caps};
use super::uapi;
use super::user;
use super::install_fd;
use inode::make_bpf_prog_inode_with_attach_target;

#[path = "prog/inode.rs"]
pub(crate) mod inode;
mod attach;
mod bind_map;
#[cfg(test)]
mod attach_tests;
#[cfg(test)]
mod bind_map_tests;
#[cfg(test)]
mod link_tests;
#[cfg(test)]
mod load_tests;

/// `char license[128]` in `bpf_prog_load()`.
const LICENSE_MAX: usize = 128;

/// `bpf_prog_load()`. # C: O(insn_cnt)
pub(super) fn load(a: &Attr, caps: Caps) -> Result<i64, Errno> {
    let p = attr::prog_load_check(a, caps, attr::unpriv_bpf_disabled())?;
    let total = p.insn_cnt as usize * uapi::INSN_SIZE as usize;
    let (mut insns, license) = load_check_attach_then(&p, || {
        // Linux copies insns then license before `find_prog_type()`.
        let insns = user::read_vec(p.insns, total)?;
        let license = read_license(p.license)?;
        Ok((insns, license))
    })?;
    if !attr::prog_type_supported(p.prog_type) { return Err(Errno::Einval); }
    let maps = relocate_maps(&mut insns)?;
    let enforce_expected_attach_type = verify(&p, gpl_compatible(&license), &insns, &maps)?;
    let inode = make_bpf_prog_inode_with_attach_target(
        p.prog_type, p.expected_attach_type, enforce_expected_attach_type,
        p.attach_btf_id, insns, maps,
    );
    install_fd(inode, "bpf-prog")
}

/// Linux validates the attach contract before either user copy.
/// # C: O(1) plus `next`
fn load_check_attach_then<T>(
    p: &attr::ProgLoad,
    next: impl FnOnce() -> Result<T, Errno>,
) -> Result<T, Errno> {
    attr::prog_load_check_attach(p.prog_type, p.expected_attach_type, p.attach_btf_id)?;
    next()
}

/// Licenses that place a program under the kernel's own terms, which is
/// what a hook may demand before it will run one.
const GPL_LICENSES: [&[u8]; 6] = [
    b"GPL", b"GPL v2", b"GPL and additional rights",
    b"Dual BSD/GPL", b"Dual MIT/GPL", b"Dual MPL/GPL",
];

/// Whether the declared license is one of those terms. # C: O(1)
fn gpl_compatible(license: &[u8]) -> bool {
    GPL_LICENSES.contains(&license)
}

/// Resolve userspace map fds embedded in `BPF_LD_IMM64`, replace them with
/// program-local indices, and return strong references pinned by the program.
/// # C: O(insn count)
fn relocate_maps(insns: &mut [u8]) -> Result<Vec<InodeRef>, Errno> {
    let mut maps = Vec::new();
    let mut pc = 0;
    while pc < insns.len() / uapi::INSN_SIZE as usize {
        let at = pc * uapi::INSN_SIZE as usize;
        if insns[at] != 0x18 {
            pc += 1;
            continue;
        }
        if pc + 1 >= insns.len() / uapi::INSN_SIZE as usize {
            return Err(Errno::Einval);
        }
        let src = insns[at + 1] >> 4;
        if !matches!(src, uapi::pseudo::MAP_FD | uapi::pseudo::MAP_VALUE) {
            pc += 2;
            continue;
        }
        let next = at + uapi::INSN_SIZE as usize;
        if insns[at + 2..at + 4] != [0, 0]
            || insns[next] != 0 || insns[next + 1] != 0
            || insns[next + 2..next + 4] != [0, 0] {
            return Err(Errno::Einval);
        }
        let fd = i32::from_le_bytes(insns[at + 4..at + 8].try_into().unwrap());
        if fd < 0 { return Err(Errno::Ebadf); }
        let inode = super::map::map_from_fd(fd as u32)?;
        if src == uapi::pseudo::MAP_FD
            && i32::from_le_bytes(insns[next + 4..next + 8].try_into().unwrap()) != 0 {
            return Err(Errno::Einval);
        }
        if src == uapi::pseudo::MAP_VALUE {
            let offset = i32::from_le_bytes(insns[next + 4..next + 8].try_into().unwrap());
            let map = inode.private::<super::BpfMapInode>().ok_or(Errno::Einval)?;
            if offset < 0 || map.map_type != uapi::map_type::ARRAY
                || offset as u32 >= map.value_size {
                return Err(Errno::Einval);
            }
        }
        let index = i32::try_from(maps.len()).map_err(|_| Errno::E2big)?;
        insns[at + 4..at + 8].copy_from_slice(&index.to_le_bytes());
        maps.push(inode);
        pc += 2;
    }
    Ok(maps)
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

/// Structural bytecode verification. Each advertised type has a matching
/// runner and verifier.
///
/// The structural rejects map onto verifier failures returning `-EINVAL`:
/// an out-of-range jump target, a final instruction that is neither an exit
/// nor a jump, an invalid register number, or an unknown opcode. An access
/// the program's context does not admit is `-EACCES` instead — the program
/// is well formed and the access is refused, which is a different answer
/// from "this is not a program". # C: O(insn_cnt)
fn verify(
    p: &attr::ProgLoad,
    gpl: bool,
    insns: &[u8],
    maps: &[InodeRef],
) -> Result<bool, Errno> {
    let verdict = match p.prog_type {
        uapi::prog_type::CGROUP_DEVICE =>
            crate::bpf_verify::verify_cgroup_device(insns).map(|()| false),
        uapi::prog_type::SOCKET_FILTER | uapi::prog_type::CGROUP_SKB
            | uapi::prog_type::CGROUP_SOCK_ADDR => {
            crate::bpf_verify::verify_program(
                p.prog_type, p.expected_attach_type, insns, maps,
            )
        }
        uapi::prog_type::LSM =>
            crate::bpf_verify::verify_lsm_program(lsm_hook(p, gpl)?, insns, maps)
                .map(|()| false),
        _ => return Err(Errno::Einval),
    };
    verdict.map_err(|error| match error {
        crate::bpf_verify::VerifyError::TooManyInsns => Errno::E2big,
        crate::bpf_verify::VerifyError::NoMemory => Errno::Enomem,
        crate::bpf_verify::VerifyError::UnsafeContextAccess => Errno::Eacces,
        _ => Errno::Einval,
    })
}

/// Hook an LSM program attaches to, resolved against the kernel's own type
/// information. The attach direction, the license and the attach target are
/// all part of the same verification step, so each failure is `-EINVAL`:
/// only `BPF_LSM_MAC` is a hook attachment, a hook will not run a program
/// released under other terms, and a target that names no published hook
/// stub has nothing to attach to.
/// # C: O(hook count)
fn lsm_hook(p: &attr::ProgLoad, gpl: bool) -> Result<crate::bpf_lsm::Hook, Errno> {
    if p.expected_attach_type != uapi::attach_type::LSM_MAC || !gpl {
        return Err(Errno::Einval);
    }
    super::btf::lsm_hook_by_btf_id(p.attach_btf_id).ok_or(Errno::Einval)
}

/// `bpf_prog_attach()` / `bpf_prog_detach()`. # C: O(descendants * programs)
pub(super) fn attach(a: &Attr, detach: bool, caps: Caps) -> Result<i64, Errno> {
    attach::attach(a, detach, caps)
}

/// `bpf_prog_query()`. # C: O(program count)
pub(super) fn query(a: &Attr, uattr: u64, uattr_size: u32, caps: Caps) -> Result<i64, Errno> {
    attach::query(a, uattr, uattr_size, caps)
}

/// `bpf_prog_get_fd_by_id()`. # C: O(log programs)
pub(super) fn get_fd_by_id(a: &Attr, caps: Caps) -> Result<i64, Errno> {
    attach::get_fd_by_id(a, caps)
}

/// Bind a map lifetime to a loaded program. # C: O(program map count)
pub(super) fn bind_map(a: &Attr) -> Result<i64, Errno> {
    bind_map::bind(a)
}

/// `bpf_link_create()`. # C: O(descendants * programs)
pub(super) fn link_create(a: &Attr, caps: Caps) -> Result<i64, Errno> {
    attach::link_create(a, caps)
}
