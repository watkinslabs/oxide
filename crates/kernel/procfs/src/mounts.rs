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
use vfs::{default_inode_ops, mk_mode, FileOps, FileType, Inode, InodeBuilder, InodeRef, KResult};

/// `/proc/mounts` + `/proc/<pid>/mounts` — fstab-style lines, one per
/// live mount: `<src> <mountpoint> <fstype> <opts> 0 0`. Built from
/// each FileSystem's `mounts_line`.
/// # C: O(N_mounts)
fn build_mounts() -> Vec<u8> {
    use core::sync::atomic::Ordering;
    let mut s = String::new();
    let root_prefix = current_root_prefix();
    for m in vfs::mount::snapshot() {
        let mp = match vfs::mount::project_path_under_root(&m.mount_point_str(), root_prefix.as_deref()) {
            Some(p) => p,
            None => continue,
        };
        let mut line = m.fs().mounts_line(&mp, Some(&**m.sb()));
        if (m.flags.load(Ordering::Acquire) & vfs::mount::MNT_RDONLY) != 0 {
            if let Some(idx) = line.find(" rw,") {
                line.replace_range(idx..idx + 4, " ro,");
            }
        }
        s.push_str(&line);
    }
    s.into_bytes()
}

fn current_root_prefix() -> Option<String> {
    let cur = sched::live::current()?;
    // SAFETY: task.root_vfs is single-mutator per task; read-only snapshot for procfs rendering.
    let rv = unsafe { (*cur.root_vfs.get()).clone() }?;
    let m = vfs::mount::mount_by_id(rv.mnt_id)?;
    let mut prefix = m.mount_point_str();
    if let Some(root) = vfs::mount::root_dentry_for_mount_id(rv.mnt_id) {
        let rp = rv.dentry.absolute_path();
        let bp = root.absolute_path();
        if rp.starts_with(bp.as_slice()) {
            let strip = if bp.as_slice() == b"/" { 0 } else { bp.len() };
            let suffix = core::str::from_utf8(&rp[strip..]).unwrap_or("");
            if prefix != "/" { prefix.push_str(suffix); }
            else if !suffix.is_empty() { prefix = String::from(suffix); }
        }
    }
    if prefix == "/" { None } else { Some(prefix) }
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
    let mounts = vfs::mount::snapshot();
    let root_prefix = current_root_prefix();
    let mut s = String::new();
    for m in mounts.iter() {
        let mp = match vfs::mount::project_path_under_root(&m.mount_point_str(), root_prefix.as_deref()) {
            Some(p) => p,
            None => continue,
        };
        let id = m.mnt_id;
        // Parent from mount-object identity (`parent_id`), not a string-prefix
        // scan. Root mounts render parent 0 (Linux mountinfo: the root has no
        // parent mount), every other mount its real parent mnt_id.
        let parent = if m.is_root() || mp == "/" { 0 } else { vfs::mount::parent_mnt_id(&m) };
        let name = m.fs().name();
        let root = vfs::mount::mountinfo_root_field(m);
        let opts = vfs::mount::mountinfo_mount_options(m);
        let opt = vfs::mount::mountinfo_optional_fields(m);
        let src = vfs::mount::mountinfo_source_field(m);
        let sb_opts = vfs::mount::mountinfo_super_options(m);
        s.push_str(&format!(
            "{} {} 0:{} {} {} {}{} - {} {} {}\n",
            id, parent, id, root, mp, opts, opt, name, src, sb_opts,
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
