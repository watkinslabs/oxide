// Dynamic `/proc/mounts` + `/proc/<pid>/mountinfo` per `19§4`. Both
// read the LIVE unified mount table (`vfs::mount::snapshot`) at read
// time instead of a hardcoded string — systemd + `mount`/`findmnt`
// parse these expecting them to reflect reality (K2 of the distro
// roadmap; "don't fake kernel state with constants").

#![cfg(target_os = "oxide-kernel")]

use alloc::format;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use sync::{MountTable as MountSnapClass, Spinlock};
use vfs::{default_inode_ops, mk_mode, File, FileOps, FileType, Inode, InodeBuilder, InodeRef, KResult, PollSubscribers, VfsError};

use crate::mount_snapshot::{MountSnapshotBuilder, OpenMountSnapshot};

static NEXT_SNAPSHOT: AtomicU64 = AtomicU64::new(1);
static SNAPSHOTS: Spinlock<BTreeMap<u64, OpenMountSnapshot>, MountSnapClass> = Spinlock::new(BTreeMap::new());

fn alloc_snapshot(tid_opt: Option<u32>, build: MountSnapshotBuilder) -> Option<u64> {
    let (namespace, root_prefix) = task_mount_context(tid_opt)?;
    let id = NEXT_SNAPSHOT.fetch_add(1, Ordering::Relaxed);
    SNAPSHOTS.lock().insert(id, OpenMountSnapshot::new(namespace, root_prefix, build));
    Some(id)
}

fn refresh_snapshot_if_needed(id: u64, force: bool, build: MountSnapshotBuilder) {
    if id == 0 { return; }
    if let Some(snapshot) = SNAPSHOTS.lock().get_mut(&id) { snapshot.refresh(force, build); }
}

fn read_snapshot(id: u64, off: u64, buf: &mut [u8]) -> Option<usize> {
    let snaps = SNAPSHOTS.lock();
    snaps.get(&id).map(|snapshot| read_body(snapshot.data(), off, buf))
}

fn poll_snapshot(id: u64) -> Option<u32> {
    let mut snaps = SNAPSHOTS.lock();
    snaps.get_mut(&id).map(OpenMountSnapshot::poll_mask)
}

fn release_snapshot(id: u64) {
    if id == 0 { return; }
    let snapshot = SNAPSHOTS.lock().remove(&id);
    drop(snapshot);
}

/// `/proc/mounts` + `/proc/<pid>/mounts` — fstab-style lines, one per
/// live mount: `<src> <mountpoint> <fstype> <opts> 0 0`. Built from
/// each mount's `vfsmount` + `super_block` state.
/// # C: O(N_mounts)
fn task_mount_context(tid_opt: Option<u32>) -> Option<(vfs::mntns::MntNamespaceRef, Option<String>)> {
    match tid_opt {
        None => sched::live::current().and_then(|task| {
            let namespace = task.mount_namespace_snapshot()?;
            Some((namespace, root_prefix_for_task(task)))
        }),
        Some(tid) => sched::live::registry::lookup(tid)
            .and_then(|task| {
                let namespace = task.mount_namespace_snapshot()?;
                Some((namespace, root_prefix_for_task(task.as_ref())))
            }),
    }
}

fn build_mounts(namespace: &vfs::mntns::MntNamespaceRef, root_prefix: Option<&str>) -> Vec<u8> {
    use core::sync::atomic::Ordering;
    let mut s = String::new();
    for m in vfs::mount::snapshot_ns_view(namespace.id()) {
        let mp = match vfs::mount::project_path_under_root(&m.mount_point_str(), root_prefix) {
            Some(p) => p,
            None => continue,
        };
        let rw = if (m.flags.load(Ordering::Acquire) & vfs::mount::MNT_RDONLY) != 0 { "ro" } else { "rw" };
        s.push_str(&vfs::mount::mountinfo_source_field(&m));
        s.push(' ');
        s.push_str(&mp);
        s.push(' ');
        s.push_str(m.sb().s_type.name());
        s.push(' ');
        s.push_str(rw);
        s.push_str(",relatime");
        s.push_str(&m.sb().show_options());
        s.push_str(" 0 0\n");
    }
    s.into_bytes()
}

fn root_prefix_for_task(cur: &sched::Task) -> Option<String> {
    // SAFETY: task.root is single-mutator per task; read-only snapshot for procfs rendering.
    let root_s = unsafe { (*cur.root.get()).clone() };
    if root_s == "/" { return None; }
    // SAFETY: task.root_vfs is single-mutator per task; read-only snapshot for procfs rendering.
    let rv = unsafe { (*cur.root_vfs.get()).clone() }?;
    let prefix = vfs::mount::render_path_for_mount(rv.mnt_id, &rv.dentry);
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
fn build_mountinfo(namespace: &vfs::mntns::MntNamespaceRef, root_prefix: Option<&str>) -> Vec<u8> {
    let ns = namespace.id();
    let mounts = vfs::mount::snapshot_ns_view(ns);
    #[cfg(feature = "debug-mnt")]
    {
        klog::write_raw(b"[MNTINFO] ns="); klog::write_dec_u64(ns);
        klog::write_raw(b" root=");
        klog::write_raw(root_prefix.unwrap_or("/").as_bytes());
        klog::write_raw(b" rows="); klog::write_dec_u64(mounts.len() as u64);
        klog::write_raw(b"\n");
    }
    let mut s = String::new();
    for m in mounts.iter() {
        let mp = match vfs::mount::project_path_under_root(&m.mount_point_str(), root_prefix) {
            Some(p) => {
                #[cfg(feature = "debug-mnt")]
                {
                    klog::write_raw(b"[MNTINFO] row id="); klog::write_dec_u64(m.mnt_id);
                    klog::write_raw(b" raw="); klog::write_raw(m.mount_point_str().as_bytes());
                    klog::write_raw(b" mp="); klog::write_raw(p.as_bytes());
                    klog::write_raw(b" type="); klog::write_raw(m.sb().s_type.name().as_bytes());
                    klog::write_raw(b"\n");
                }
                p
            }
            None => continue,
        };
        let id = m.mnt_id;
        // Parent from mount-object identity (`parent_id`), not a string-prefix
        // scan. Root mounts render parent 0 (Linux mountinfo: the root has no
        // parent mount), every other mount its real parent mnt_id.
        let parent = if m.is_root() || mp == "/" { 0 } else { vfs::mount::parent_mnt_id(&m) };
        let name = m.sb().s_type.name();
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
    fn on_open_file(&self, file: &File) -> KResult<()> {
        let d = file.inode().private::<ProcMountsData>().ok_or(VfsError::Einval)?;
        file.set_private_data(alloc_snapshot(d.tid_opt, build_mounts).ok_or(VfsError::Enoent)?);
        Ok(())
    }
    fn read_file(&self, file: &File, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let id = file.private_data();
        if id == 0 { return Err(VfsError::Einval); }
        refresh_snapshot_if_needed(id, off == 0, build_mounts);
        read_snapshot(id, off, buf).ok_or(VfsError::Einval)
    }
    fn on_release_file(&self, file: &File) {
        release_snapshot(file.private_data());
    }
}

pub struct ProcMountsData { tid_opt: Option<u32> }

/// `/proc/mounts` and `/proc/<pid>/mounts`. # C: O(1)
pub fn make_proc_mounts(tid_opt: Option<u32>) -> InodeRef {
    InodeBuilder::new(crate::ids::MOUNTS, mk_mode(FileType::Regular, 0o444), default_inode_ops(), Arc::new(MountsFileOps))
        .private(Arc::new(ProcMountsData { tid_opt }))
        .build()
}

/// Target selector used only to capture exact open-time mount state.
pub struct MountinfoData {
    tid_opt: Option<u32>,
}

/// `i_fop` for `/proc/<pid>/mountinfo` — renders the richer mountinfo(5)
/// format and reports mount-change readiness via `poll`.
struct MountinfoFileOps;
impl FileOps for MountinfoFileOps {
    fn on_open_file(&self, file: &File) -> KResult<()> {
        let d = file.inode().private::<MountinfoData>().ok_or(VfsError::Einval)?;
        file.set_private_data(alloc_snapshot(d.tid_opt, build_mountinfo).ok_or(VfsError::Enoent)?);
        Ok(())
    }
    fn read_file(&self, file: &File, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let id = file.private_data();
        if id == 0 { return Err(VfsError::Einval); }
        refresh_snapshot_if_needed(id, off == 0, build_mountinfo);
        read_snapshot(id, off, buf).ok_or(VfsError::Einval)
    }
    /// POLLPRI|POLLERR when the mount generation advanced since the last poll
    /// (always POLLIN — mountinfo is always readable). # C: O(1)
    fn poll(&self, _inode: &Inode) -> u32 { vfs::POLL_IN }
    fn poll_open_file(&self, file: &File) -> u32 {
        poll_snapshot(file.private_data()).unwrap_or_else(|| self.poll(file.inode()))
    }
    fn on_release_file(&self, file: &File) {
        release_snapshot(file.private_data());
    }
}

/// `/proc/self/mountinfo` and `/proc/<pid>/mountinfo`. # C: O(1)
pub fn make_proc_mountinfo(tid_opt: Option<u32>) -> InodeRef {
    let subs = Arc::new(PollSubscribers::new());
    vfs::mntns::attach_mountinfo_poll(Arc::clone(&subs));
    InodeBuilder::new(crate::ids::MOUNTINFO, mk_mode(FileType::Regular, 0o444), default_inode_ops(), Arc::new(MountinfoFileOps))
        .private(Arc::new(MountinfoData {
            tid_opt,
        }))
        .poll_subs_arc(subs)
        .build()
}
