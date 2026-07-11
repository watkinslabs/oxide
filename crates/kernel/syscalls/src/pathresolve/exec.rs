#![cfg(target_os = "oxide-kernel")]

use super::lookup::resolve_path_raw;

/// # C: O(components) + O(size/PAGE)
pub fn read_exec(path: &[u8]) -> Option<alloc::vec::Vec<u8>> {
    let s = exec_lookup_path(path);
    let inode = resolve_path_raw(&s, false).ok()?.inode;
    read_exec_inode(&inode)
}

fn exec_lookup_path(path: &[u8]) -> alloc::string::String {
    vfs::path_from_bytes(path)
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
