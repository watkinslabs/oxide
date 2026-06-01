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
/// `<id> <parent> <maj>:<min> <root> <mp> <opts> [<optional>] - <fstype> <src> <super>`.
/// `id` is the mount's persistent `mnt_id`; `parent` is the real
/// parent mount's id (longest proper path-prefix), so the tree
/// systemd/findmnt reconstruct is accurate. The optional field
/// carries propagation: `shared:<id>` for a shared mount (its own
/// peer group until propagation events land), `unbindable` for an
/// unbindable mount, empty otherwise.
/// # C: O(N_mounts²) (parent_id_of is O(N) per mount)
fn build_mountinfo() -> Vec<u8> {
    use core::sync::atomic::Ordering;
    use vfs::mount::Propagation;
    let mounts = vfs::mount::snapshot();
    let mut s = String::new();
    for m in mounts.iter() {
        let id = m.mnt_id;
        let parent = vfs::mount::parent_id_of(&m.mount_point);
        let name = m.fs.name();
        let pg = m.peer_group.load(Ordering::Acquire);
        let opt = match Propagation::from_u8(m.propagation.load(Ordering::Acquire)) {
            // Real peer-group id (`docs/16§6`), distinct from mnt_id.
            Propagation::Shared => format!(" shared:{}", pg),
            // A slave of peer group `pg` reports `master:<pg>`; with no
            // group yet it renders as private.
            Propagation::Slave if pg != 0 => format!(" master:{}", pg),
            Propagation::Unbindable => " unbindable".into(),
            Propagation::Slave | Propagation::Private => String::new(),
        };
        s.push_str(&format!(
            "{} {} 0:{} / {} rw,relatime{} - {} {} rw\n",
            id, parent, id, m.mount_point, opt, name, name,
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
