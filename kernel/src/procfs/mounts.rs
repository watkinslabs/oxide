// Dynamic `/proc/mounts` + `/proc/<pid>/mountinfo` per `19§4`. Both
// read the LIVE unified mount table (`vfs::mount::snapshot`) at read
// time instead of a hardcoded string — systemd + `mount`/`findmnt`
// parse these expecting them to reflect reality (K2 of the distro
// roadmap; "don't fake kernel state with constants").

#![cfg(target_os = "oxide-kernel")]

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

/// `/proc/mounts` + `/proc/<pid>/mounts` — fstab-style lines, one per
/// live mount: `<src> <mountpoint> <fstype> <opts> 0 0`. Built from
/// each FileSystem's `mounts_line`.
/// # C: O(N_mounts)
fn build_mounts() -> Vec<u8> {
    let mut s = String::new();
    for m in vfs::mount::snapshot() {
        s.push_str(&m.fs.mounts_line(&m.mount_point));
    }
    s.into_bytes()
}

/// `/proc/<pid>/mountinfo` — the richer mountinfo(5) format:
/// `<id> <parent> <maj>:<min> <root> <mp> <opts> - <fstype> <src> <super>`.
/// IDs are synthesized from table order (root mount = id 1, parent of
/// the rest); enough for systemd/util-linux to parse the mount set.
/// # C: O(N_mounts)
fn build_mountinfo() -> Vec<u8> {
    let mounts = vfs::mount::snapshot();
    // Find the root mount's id so non-root mounts can point at it.
    let root_id = mounts.iter().position(|m| m.mount_point == "/").map(|i| i + 1).unwrap_or(1);
    let mut s = String::new();
    for (i, m) in mounts.iter().enumerate() {
        let id = i + 1;
        let parent = if m.mount_point == "/" { 0 } else { root_id };
        let name = m.fs.name();
        s.push_str(&format!(
            "{} {} 0:{} / {} rw,relatime - {} {} rw\n",
            id, parent, id, m.mount_point, name, name,
        ));
    }
    s.into_bytes()
}

/// Shared read body: copy `data[off..]` into `buf`.
/// # C: O(min(buf, data))
fn read_body(data: &[u8], off: u64, buf: &mut [u8]) -> usize {
    if off as usize >= data.len() { return 0; }
    let n = core::cmp::min(buf.len(), data.len() - off as usize);
    buf[..n].copy_from_slice(&data[off as usize..off as usize + n]);
    n
}

/// `/proc/mounts` and `/proc/<pid>/mounts`.
pub struct ProcMountsInode;
impl Inode for ProcMountsInode {
    fn ino(&self) -> Ino { 0x3000_0D01 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { build_mounts().len() as u64 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        Ok(read_body(&build_mounts(), off, buf))
    }
}

/// `/proc/self/mountinfo` and `/proc/<pid>/mountinfo`.
pub struct ProcMountinfoInode;
impl Inode for ProcMountinfoInode {
    fn ino(&self) -> Ino { 0x3000_0D02 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { build_mountinfo().len() as u64 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        Ok(read_body(&build_mountinfo(), off, buf))
    }
}
