#![cfg(target_os = "oxide-kernel")]

use super::at::resolve_cwd;
use super::lookup::resolve_path;
use super::root::root_dentry;

/// # C: O(components) + O(size/PAGE)
pub fn read_exec(path: &[u8]) -> Option<alloc::vec::Vec<u8>> {
    let s = core::str::from_utf8(path).ok()?;
    let abs = resolve_cwd(s);
    if let Some((tid_opt, fd)) = vfs::path::dup_fd_target(&abs) {
        let file = sched::proclink::proc_fd_file(tid_opt, fd)?;
        return read_exec_inode(file.inode());
    }
    if root_dentry().is_none() { return None; }
    let inode = resolve_path(abs.as_str(), false)?.inode;
    read_exec_inode(&inode)
}

/// # C: O(size/PAGE)
pub fn read_exec_inode(inode: &vfs::InodeRef) -> Option<alloc::vec::Vec<u8>> {
    if inode.file_type() != vfs::FileType::Regular { return None; }
    let total = inode.size() as usize;
    let mut out = alloc::vec::Vec::with_capacity(total);
    out.resize(total, 0u8);
    let mut off = 0usize;
    while off < total {
        match inode.read(off as u64, &mut out[off..]) {
            Ok(0) => break,
            Ok(n) => off += n,
            Err(_) => return None,
        }
    }
    out.truncate(off);
    Some(out)
}
