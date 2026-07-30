extern crate alloc;

use alloc::sync::Arc;
use syscall::errno::Errno;
use vfs::{FileType, InodeBuilder, default_file_ops, default_inode_ops, mk_mode};

use super::super::{BPF_FD_MODE, ids, install_fd_access, log, user};
use super::attr;
use super::format::MAX_RAW_SIZE;
use super::object::{self, BtfObject};
use super::parse;
use crate::bpf::attr::{Attr, Caps};

const BTF_FD_NAME: &str = "btf";

fn inode(object: Arc<BtfObject>) -> vfs::InodeRef {
    InodeBuilder::new(
        ids::INO_BTF,
        mk_mode(FileType::Regular, BPF_FD_MODE),
        default_inode_ops(),
        default_file_ops(),
    )
    .size(object.raw().len() as u64)
    .private(object)
    .build()
}

/// Validate, publish, and return a descriptor for one user BTF object.
/// # C: O(input bytes + type graph)
pub(crate) fn load(
    a: &Attr,
    attr_ptr: u64,
    attr_size: u32,
    common: Option<user::CommonAttr>,
    caps: Caps,
) -> Result<i64, Errno> {
    use super::super::uapi::off::btf_load as o;
    let verifier_log = log::Log::select(
        log::LegacyLog {
            buffer: a.u64_at(o::LOG_BUF),
            size: a.u32_at(o::LOG_SIZE),
            level: a.u32_at(o::LOG_LEVEL),
            true_size_ptr: (attr_size as usize
                >= o::LOG_TRUE_SIZE + core::mem::size_of::<u32>())
                .then(|| attr_ptr + o::LOG_TRUE_SIZE as u64),
        },
        common,
    )?;
    let request = attr::load(a, caps)?;
    let size = request.size as usize;
    if size > MAX_RAW_SIZE { return Err(Errno::E2big); }
    let raw = user::read_vec(request.data, size)?;
    let index = verifier_log.finish(parse::parse(&raw))?;
    let object = BtfObject::register(raw, index)?;
    install_fd_access(inode(object), BTF_FD_NAME, vfs::OpenFlags::O_RDONLY)
}

/// Open a new read-only descriptor for a live BTF object ID.
/// # C: O(log(live objects) + fd words)
pub(crate) fn get_fd_by_id(a: &Attr, caps: Caps) -> Result<i64, Errno> {
    let id = attr::get_fd_by_id(a, caps)?;
    let object = object::get_by_id(id)?;
    install_fd_access(inode(object), BTF_FD_NAME, vfs::OpenFlags::O_RDONLY)
}

/// Copy the least live BTF ID greater than the requested starting ID.
/// # C: O(log(live objects))
pub(crate) fn get_next_id(a: &Attr, attr_ptr: u64, caps: Caps) -> Result<i64, Errno> {
    let start = attr::get_next_id(a, caps)?;
    let next = object::next_id(start)?;
    let output = attr_ptr
        .checked_add(super::super::uapi::off::object_id::NEXT_ID as u64)
        .ok_or(Errno::Efault)?;
    user::write_bytes(output, &next.to_ne_bytes())?;
    Ok(0)
}
