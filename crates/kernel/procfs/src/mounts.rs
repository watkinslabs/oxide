// Dynamic `/proc/mounts` + `/proc/<pid>/mountinfo` per `19§4`. Both
// read the LIVE unified mount table (`vfs::mount::snapshot`) at read
// time instead of a hardcoded string — systemd + `mount`/`findmnt`
// parse these expecting them to reflect reality (K2 of the distro
// roadmap; "don't fake kernel state with constants").

#![cfg(target_os = "oxide-kernel")]

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::AtomicU64;
use vfs::{default_inode_ops, mk_mode, FileOps, FileType, Ino, Inode, InodeBuilder, InodeRef, KResult};

/// `/proc/mounts` + `/proc/<pid>/mounts` — fstab-style lines, one per
/// live mount: `<src> <mountpoint> <fstype> <opts> 0 0`. Built from
/// each FileSystem's `mounts_line`.
/// # C: O(N_mounts)
fn build_mounts() -> Vec<u8> {
    use core::sync::atomic::Ordering;
    let mut s = String::new();
    for m in vfs::mount::snapshot() {
        let mut line = m.fs().mounts_line(&m.mount_point_str(), Some(&**m.sb()));
        if (m.flags.load(Ordering::Acquire) & vfs::mount::MNT_RDONLY) != 0 {
            if let Some(idx) = line.find(" rw,") {
                line.replace_range(idx..idx + 4, " ro,");
            }
        }
        s.push_str(&line);
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
/// # C: O(N_mounts) (parent_mnt_id reads the attach-time stored parent id)
fn build_mountinfo() -> Vec<u8> {
    use core::sync::atomic::Ordering;
    use vfs::mount::Propagation;
    let mounts = vfs::mount::snapshot();
    let mut s = String::new();
    for m in mounts.iter() {
        let id = m.mnt_id;
        // Parent from mount-object identity (`parent_id`), not a string-prefix
        // scan. Root mounts render parent 0 (Linux mountinfo: the root has no
        // parent mount), every other mount its real parent mnt_id.
        let parent = if m.is_root() { 0 } else { vfs::mount::parent_mnt_id(&m) };
        let name = m.fs().name();
        let pg = m.peer_group.load(Ordering::Acquire);
        let rw = if (m.flags.load(Ordering::Acquire) & vfs::mount::MNT_RDONLY) != 0 {
            "ro"
        } else {
            "rw"
        };
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
            "{} {} 0:{} / {} {},relatime{} - {} {} {}\n",
            id, parent, id, m.mount_point_str(), rw, opt, name, name, rw,
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

/// `i_fop` for `/proc/mounts` — renders the live mount table on each read.
struct MountsFileOps;
impl FileOps for MountsFileOps {
    fn read(&self, _inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        Ok(read_body(&build_mounts(), off, buf))
    }
}

/// `/proc/mounts` and `/proc/<pid>/mounts`. # C: O(1)
pub fn make_proc_mounts() -> InodeRef {
    InodeBuilder::new(0x3000_0D01, mk_mode(FileType::Regular, 0o444), default_inode_ops(), Arc::new(MountsFileOps))
        .build()
}

/// `i_private` for `/proc/<pid>/mountinfo`: `last_seen` holds the reader's
/// last-observed mount generation so `poll` returns POLLPRI when the mount
/// table changed (libmount's mount-change wakeup, `19§4`).
pub struct MountinfoData { last_seen: AtomicU64 }

/// `i_fop` for `/proc/<pid>/mountinfo` — renders the richer mountinfo(5)
/// format and reports mount-change readiness via `poll`.
struct MountinfoFileOps;
impl FileOps for MountinfoFileOps {
    fn read(&self, _inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        Ok(read_body(&build_mountinfo(), off, buf))
    }
    /// POLLPRI|POLLERR when the mount generation advanced since the last poll
    /// (always POLLIN — mountinfo is always readable). # C: O(1)
    fn poll(&self, inode: &Inode) -> u32 {
        match inode.private::<MountinfoData>() {
            Some(d) => vfs::mount::mountinfo_poll_mask(&d.last_seen),
            None => vfs::POLL_IN,
        }
    }
}

/// `/proc/self/mountinfo` and `/proc/<pid>/mountinfo`. # C: O(1)
pub fn make_proc_mountinfo() -> InodeRef {
    InodeBuilder::new(0x3000_0D02, mk_mode(FileType::Regular, 0o444), default_inode_ops(), Arc::new(MountinfoFileOps))
        .private(Arc::new(MountinfoData { last_seen: AtomicU64::new(vfs::mount::mount_generation()) }))
        .build()
}
