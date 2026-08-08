// `bpf(2)` — syscall slot 321 (x86_64) / 280 (aarch64 generic ABI),
// per `27§5`. Module manifest; no policy lives here.
//
//   uapi.rs      `enum bpf_cmd`, `union bpf_attr` offsets, BPF_F_* flags
//   attr.rs      attr size protocol, CHECK_ATTR, capability ladders
//                (no target gate — hosted-tested in attr/tests.rs)
//   user.rs      user-memory access for the attr + insn + key/value copies
//   dispatch.rs  the command table and the per-call capability snapshot
//   cmd/         one module per command whose object is not a prog/map/btf:
//                test_run, next_id, links, stats, batch, and the ladders
//                whose backing subsystem this kernel does not have
//   prog.rs      PROG_LOAD, PROG_ATTACH/DETACH, LINK_CREATE, program object
//   map.rs       MAP_CREATE, the element/freeze commands, map object
//   link.rs      cgroup and LSM link objects and the link id registry
//   fd.rs        descriptor publication for every fd-backed object
//   sk_filter.rs socket-filter `__sk_buff` context build and run entry
//   ids.rs       pseudo-inode numbers for fd-backed objects

extern crate alloc;
use alloc::sync::Arc;

use syscall::SyscallArgs;
use syscall::errno::Errno;
use vfs::{FileType, InodeRef, InodeBuilder, default_inode_ops, default_file_ops, mk_mode};

pub mod uapi;
pub mod attr;
mod user;
mod dispatch;
// Directory `bpf/cmd/`; the module is `command` because `cmd` names the
// UAPI command-number module this file already imports.
#[path = "bpf/cmd.rs"]
mod command;
mod prog;
mod cgroup_device;
mod cgroup_network;
mod btf;
mod log;
mod link;
mod fd;
pub mod sk_filter;
pub(crate) mod map;
mod ids;
mod token;
mod object;

use uapi::cmd;

pub(super) const BPF_FD_MODE: u16 = 0o600;

pub use prog::inode::{
    BpfProgInode, make_bpf_prog_inode, make_bpf_prog_inode_with_meta,
    make_bpf_prog_inode_with_contract, make_bpf_prog_inode_with_attach_target,
    NO_ATTACH_TARGET,
};
pub use map::inode::{BpfMapInode, make_bpf_map_inode};
pub use link::{
    BpfCgroupLinkInode, BpfLsmLinkInode, make_bpf_cgroup_link_inode, make_bpf_lsm_link_inode,
};
pub(crate) use link::prime_bpf_cgroup_link;
pub(crate) use fd::{install_fd, install_fd_access};

/// Map value storage is separately locked so a helper can pin a value
/// without holding the map's directory lock while the interpreter runs.
pub(crate) use map::BpfMapValue;

/// Re-exported for `SO_ATTACH_BPF` in the setsockopt slot.
pub use uapi::prog_type::SOCKET_FILTER as BPF_PROG_TYPE_SOCKET_FILTER;
pub use cgroup_device::{
    DEVCG_ACC_MKNOD, DEVCG_ACC_READ, DEVCG_ACC_WRITE, DEVCG_DEV_BLOCK, DEVCG_DEV_CHAR,
    check as check_device_access,
};
pub(crate) use cgroup_device::inode_permission as cgroup_device_inode_permission;
pub use cgroup_network::{
    CgroupSkbAttach, CgroupSkbContext, CgroupSkbVerdict, CgroupSockAddrAttach,
    CgroupSockAddrContext, CgroupSockAddrError, CgroupSockAddrVerdict,
    run_cgroup_skb, run_cgroup_sock_addr,
};

/// Delegation token derived from a bpffs superblock.
pub struct BpfTokenInode {
    pub source_magic: u64,
    pub flags: u32,
}

pub(crate) const BPF_FS_MAGIC: u64 = 0xcafe4a11;

/// Build the `Arc<Inode>` for a bpffs delegation token. # C: O(1)
pub fn make_bpf_token_inode(token: BpfTokenInode) -> InodeRef {
    InodeBuilder::new(ids::INO_TOKEN, mk_mode(FileType::Regular, BPF_FD_MODE),
        default_inode_ops(), default_file_ops())
        .private(Arc::new(token))
        .build()
}

/// `sys_bpf(cmd, attr, size, attr_common, size_common)` — slot 321.
/// # C: O(1) admit; O(log N) for map ops; O(insn_cnt) for PROG_LOAD
pub fn sys_bpf(args: &SyscallArgs) -> i64 {
    match dispatch::dispatch(args) { Ok(v) => v, Err(e) => -(e.as_i32() as i64) }
}

/// Decode the `BPF_OBJ_PIN` pathname after the common attribute protocol.
/// The syscall shim resolves this address through the caller's mount namespace.
/// # C: O(sizeof(bpf_attr))
pub fn obj_pin_path(args: &SyscallArgs) -> Result<u64, Errno> {
    let attr = dispatch::object_attr(args)?;
    attr::check_attr(&attr, uapi::off::obj_pin::LAST_END)?;
    Ok(attr.u64_at(uapi::off::obj_pin::PATHNAME))
}

/// Decode the `BPF_OBJ_GET` pathname after the common attribute protocol.
/// # C: O(sizeof(bpf_attr))
pub fn obj_get_path(args: &SyscallArgs) -> Result<u64, Errno> {
    let attr = dispatch::object_attr(args)?;
    attr::check_attr(&attr, uapi::off::obj_get::LAST_END)?;
    Ok(attr.u64_at(uapi::off::obj_get::PATHNAME))
}

/// Whether this command must be pathname-resolved by the syscall shim.
/// # C: O(1)
pub fn object_path_command(args: &SyscallArgs) -> Option<u32> {
    let c = (args.a0 as u32) & !cmd::COMMON_ATTRS;
    matches!(c, cmd::OBJ_PIN | cmd::OBJ_GET).then_some(c)
}

/// Publish an fd-backed BPF object under an already-resolved bpffs parent.
/// # C: O(log directory entries)
pub fn obj_pin(args: &SyscallArgs, parent: &vfs::VfsPath, name: &str) -> Result<i64, Errno> {
    object::pin(&dispatch::object_attr(args)?, parent, name, dispatch::caps_now()?)
}

/// Recover an fd for an already-resolved bpffs object.
/// # C: O(fd words)
pub fn obj_get(args: &SyscallArgs, object: &vfs::VfsPath) -> Result<i64, Errno> {
    object::get(&dispatch::object_attr(args)?, object, dispatch::caps_now()?)
}
