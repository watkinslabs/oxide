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

struct OpenMountSnapshot {
    tid_opt: Option<u32>,
    ns: u64,
    data_seen: u64,
    poll_seen: u64,
    data: Vec<u8>,
}

static NEXT_SNAPSHOT: AtomicU64 = AtomicU64::new(1);
static SNAPSHOTS: Spinlock<BTreeMap<u64, OpenMountSnapshot>, MountSnapClass> = Spinlock::new(BTreeMap::new());

fn alloc_snapshot(tid_opt: Option<u32>, data: Vec<u8>) -> u64 {
    let id = NEXT_SNAPSHOT.fetch_add(1, Ordering::Relaxed);
    SNAPSHOTS.lock().insert(id, OpenMountSnapshot {
        tid_opt,
        ns: task_mount_ns(tid_opt),
        data_seen: vfs::mntns::ns_seq(task_mount_ns(tid_opt)),
        poll_seen: vfs::mntns::ns_seq(task_mount_ns(tid_opt)),
        data,
    });
    id
}

fn refresh_snapshot(id: u64, data: Vec<u8>) {
    let mut snaps = SNAPSHOTS.lock();
    if let Some(s) = snaps.get_mut(&id) {
        s.ns = task_mount_ns(s.tid_opt);
        s.data_seen = vfs::mntns::ns_seq(s.ns);
        s.data = data;
    }
}

fn snapshot_changed(id: u64, tid_opt: Option<u32>) -> bool {
    let snaps = SNAPSHOTS.lock();
    let Some(s) = snaps.get(&id) else { return false; };
    let ns = task_mount_ns(tid_opt);
    ns != s.ns || vfs::mntns::ns_seq(ns) != s.data_seen
}

fn refresh_snapshot_if_needed(id: u64, tid_opt: Option<u32>, force: bool, build: fn(Option<u32>) -> Vec<u8>) {
    if id == 0 { return; }
    if force || snapshot_changed(id, tid_opt) { refresh_snapshot(id, build(tid_opt)); }
}

fn read_snapshot(id: u64, off: u64, buf: &mut [u8]) -> Option<usize> {
    let snaps = SNAPSHOTS.lock();
    snaps.get(&id).map(|s| read_body(&s.data, off, buf))
}

fn poll_snapshot(id: u64) -> Option<u32> {
    let mut snaps = SNAPSHOTS.lock();
    let s = snaps.get_mut(&id)?;
    let ns = task_mount_ns(s.tid_opt);
    let cur = vfs::mntns::ns_seq(ns);
    let changed = cur != s.poll_seen || ns != s.ns;
    s.ns = ns;
    s.poll_seen = cur;
    Some(if changed { vfs::POLL_IN | vfs::POLL_PRI | vfs::POLL_ERR } else { vfs::POLL_IN })
}

fn release_snapshot(id: u64) {
    if id != 0 { SNAPSHOTS.lock().remove(&id); }
}

/// `/proc/mounts` + `/proc/<pid>/mounts` — fstab-style lines, one per
/// live mount: `<src> <mountpoint> <fstype> <opts> 0 0`. Built from
/// each mount's `vfsmount` + `super_block` state.
/// # C: O(N_mounts)
fn task_mount_ns(tid_opt: Option<u32>) -> u64 {
    match tid_opt {
        None => sched::live::current()
            .and_then(|t| t.mount_namespace_snapshot().map(|namespace| namespace.id())),
        Some(tid) => sched::live::registry::lookup(tid)
            .and_then(|t| t.mount_namespace_snapshot().map(|namespace| namespace.id())),
    }
        .unwrap_or(0)
}

fn build_mounts(tid_opt: Option<u32>) -> Vec<u8> {
    use core::sync::atomic::Ordering;
    let mut s = String::new();
    let root_prefix = current_root_prefix(tid_opt);
    for m in vfs::mount::snapshot_ns_view(task_mount_ns(tid_opt)) {
        let mp = match vfs::mount::project_path_under_root(&m.mount_point_str(), root_prefix.as_deref()) {
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

fn current_root_prefix(tid_opt: Option<u32>) -> Option<String> {
    match tid_opt {
        None => sched::live::current().and_then(root_prefix_for_task),
        Some(tid) => sched::live::registry::lookup(tid)
            .and_then(|t| root_prefix_for_task(t.as_ref())),
    }
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
fn build_mountinfo(tid_opt: Option<u32>) -> Vec<u8> {
    let ns = task_mount_ns(tid_opt);
    let mounts = vfs::mount::snapshot_ns_view(ns);
    let root_prefix = current_root_prefix(tid_opt);
    #[cfg(feature = "debug-mnt")]
    {
        klog::write_raw(b"[MNTINFO] tid=");
        match tid_opt {
            Some(tid) => klog::write_dec_u64(tid as u64),
            None => klog::write_raw(b"self"),
        }
        klog::write_raw(b" ns="); klog::write_dec_u64(ns);
        klog::write_raw(b" root=");
        klog::write_raw(root_prefix.as_deref().unwrap_or("/").as_bytes());
        klog::write_raw(b" rows="); klog::write_dec_u64(mounts.len() as u64);
        klog::write_raw(b"\n");
    }
    let mut s = String::new();
    for m in mounts.iter() {
        let mp = match vfs::mount::project_path_under_root(&m.mount_point_str(), root_prefix.as_deref()) {
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
        file.set_private_data(alloc_snapshot(d.tid_opt, build_mounts(d.tid_opt)));
        Ok(())
    }
    fn read_file(&self, file: &File, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let inode = file.inode();
        let d = inode.private::<ProcMountsData>().ok_or(VfsError::Einval)?;
        let id = file.private_data();
        if id == 0 { return Ok(read_body(&build_mounts(d.tid_opt), off, buf)); }
        refresh_snapshot_if_needed(id, d.tid_opt, off == 0, build_mounts);
        Ok(read_snapshot(id, off, buf).unwrap_or_else(|| read_body(&build_mounts(d.tid_opt), off, buf)))
    }
    fn on_release_file(&self, file: &File) {
        release_snapshot(file.private_data());
    }
}

pub struct ProcMountsData { tid_opt: Option<u32> }

/// `/proc/mounts` and `/proc/<pid>/mounts`. # C: O(1)
pub fn make_proc_mounts(tid_opt: Option<u32>) -> InodeRef {
    InodeBuilder::new(0x3000_0D01, mk_mode(FileType::Regular, 0o444), default_inode_ops(), Arc::new(MountsFileOps))
        .private(Arc::new(ProcMountsData { tid_opt }))
        .build()
}

/// `i_private` for `/proc/<pid>/mountinfo`: `last_seen` holds the reader's
/// last-observed mount generation so `poll` returns POLLPRI when the mount
/// table changed (libmount's mount-change wakeup, `19§4`).
pub struct MountinfoData {
    tid_opt: Option<u32>,
    last_seen: AtomicU64,
}

/// `i_fop` for `/proc/<pid>/mountinfo` — renders the richer mountinfo(5)
/// format and reports mount-change readiness via `poll`.
struct MountinfoFileOps;
impl FileOps for MountinfoFileOps {
    fn on_open_file(&self, file: &File) -> KResult<()> {
        let d = file.inode().private::<MountinfoData>().ok_or(VfsError::Einval)?;
        file.set_private_data(alloc_snapshot(d.tid_opt, build_mountinfo(d.tid_opt)));
        Ok(())
    }
    fn read_file(&self, file: &File, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let inode = file.inode();
        let d = inode.private::<MountinfoData>().ok_or(VfsError::Einval)?;
        let id = file.private_data();
        if id == 0 { return Ok(read_body(&build_mountinfo(d.tid_opt), off, buf)); }
        refresh_snapshot_if_needed(id, d.tid_opt, off == 0, build_mountinfo);
        Ok(read_snapshot(id, off, buf).unwrap_or_else(|| read_body(&build_mountinfo(d.tid_opt), off, buf)))
    }
    /// POLLPRI|POLLERR when the mount generation advanced since the last poll
    /// (always POLLIN — mountinfo is always readable). # C: O(1)
    fn poll(&self, inode: &Inode) -> u32 {
        match inode.private::<MountinfoData>() {
            Some(d) => vfs::mount::mountinfo_poll_mask_ns(task_mount_ns(d.tid_opt), &d.last_seen),
            None => vfs::POLL_IN,
        }
    }
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
    InodeBuilder::new(0x3000_0D02, mk_mode(FileType::Regular, 0o444), default_inode_ops(), Arc::new(MountinfoFileOps))
        .private(Arc::new(MountinfoData {
            tid_opt,
            last_seen: AtomicU64::new(vfs::mntns::ns_seq(task_mount_ns(tid_opt))),
        }))
        .poll_subs_arc(subs)
        .build()
}
