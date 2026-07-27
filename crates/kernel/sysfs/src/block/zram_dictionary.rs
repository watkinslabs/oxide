//! Sysfs-owned loading of Linux zram compressor dictionary files.

use alloc::vec::Vec;

use vfs::{File, FileType, KResult, LookupFlags, OpenFlags, VfsError, VfsPath};
use vfs::namei::root_dentry;

/// Linux `kernel_read_file_from_path()` accepts dictionary files through its
/// signed-int byte-count interface, not an unbounded userspace allocation.
const MAX_DICTIONARY_BYTES: usize = i32::MAX as usize;

/// Return the final `dict=<path>` argument parsed by Linux's `next_arg` loop.
/// # C: O(text bytes)
pub(super) fn dictionary_path(text: &str) -> Option<&str> {
    text.split_ascii_whitespace().filter_map(|item| item.split_once('='))
        .filter(|(name, value)| *name == "dict" && !value.is_empty()).map(|(_, value)| value).last()
}

fn namespace_root() -> KResult<VfsPath> {
    let dentry = root_dentry().ok_or(VfsError::Enoent)?;
    let ns = vfs::mount::current_ns();
    let (mnt_id, dentry) = vfs::mount::namespace_root_path(ns, &dentry)
        .unwrap_or((vfs::mount::MNT_ID_NONE, dentry));
    let inode = dentry.inode().ok_or(VfsError::Enoent)?;
    Ok(VfsPath { mnt_id, dentry, inode, last_component: None })
}

/// Snapshot the writer's live cwd/root `struct path` pair.  sysfs calls this
/// in the original write context, exactly where Linux opens `dict=<path>`.
/// # C: O(1)
fn writer_paths() -> KResult<(VfsPath, VfsPath)> {
    let root = sched::proclink::task_root_vfs(None).unwrap_or(namespace_root()?);
    let start = sched::proclink::task_cwd_vfs(None).unwrap_or_else(|_| root.clone());
    Ok((start, root))
}

/// Copy a zram LZ4 dictionary at sysfs-write time.  The returned allocation is
/// passed to drv-zram, which owns it for the immutable initialized lifetime.
/// # C: O(file bytes)
pub(super) fn read_dictionary(path: &str) -> KResult<Vec<u8>> {
    let (start, root) = writer_paths()?;
    let cred = sched::cred::current_vfs_cred();
    let resolved = vfs::path_lookup_at_root_cred(
        start.dentry, start.mnt_id, root.dentry, root.mnt_id, path,
        LookupFlags::default(), cred.clone(),
    )?;
    if resolved.inode.file_type() != FileType::Regular { return Err(VfsError::Einval); }
    vfs::inode_permission(&resolved.inode, vfs::MAY_READ, &cred)?;
    let length = usize::try_from(resolved.inode.size()).map_err(|_| VfsError::Einval)?;
    if length > MAX_DICTIONARY_BYTES { return Err(VfsError::Einval); }
    let file = File::new_at(
        resolved.inode, resolved.dentry, OpenFlags::O_RDONLY, resolved.mnt_id,
        sched::cred::current_vfs_file_cred(),
    );
    file.open_hook()?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(|_| VfsError::Enomem)?;
    while bytes.len() < length {
        let offset = bytes.len();
        bytes.resize(length, 0);
        let count = file.read(&mut bytes[offset..])?;
        bytes.truncate(offset + count);
        if count == 0 { break; }
    }
    Ok(bytes)
}
