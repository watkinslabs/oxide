// `FAN_REPORT_MNT` / `FAN_MARK_MNTNS` hosted tests: a real mount is grafted and
// detached through the vfs mount API and the group is read back, so the
// PRODUCTION notification path runs — the hook install, the mount-tree choke
// point, the mark match, the queue admission, and the wire encoding. A test
// that called the fire function by name would prove only that the function
// exists.
//
// The mount table and the group registry are process-wide, so these tests
// serialize against each other and assert on the records naming the mounts
// THEY created.
//
// Included as a child module of `inotify` via `#[path]`, so `use super::*`
// reaches the module-private mark/dispatch items.

use super::*;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use std::sync::{Mutex, MutexGuard};

use crate::inotify::fan_layout::{FAN_EVENT_METADATA_LEN, FAN_NOFD};
use crate::inotify::fan_mnt::{install_mnt_hook, FAN_EVENT_INFO_TYPE_MNT, MNT_INFO_LEN};
use crate::inotify::syscalls::{apply_mark_ns, mnt_ns_from_inode};
use crate::inotify::types::{FAN_MNT_DETACH, MNTNS_MARK_COUNT};
use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::superblock::{FileSystemType, SuperBlock};
use vfs::{default_file_ops, default_inode_ops, mk_mode, Dentry, FileType, InodeBuilder, InodeOps,
    InodeRef, KResult, VfsError};

const MNT_EVENTS: u32 = FAN_MNT_ATTACH | FAN_MNT_DETACH;

static SERIAL: Mutex<()> = Mutex::new(());
fn guard() -> MutexGuard<'static, ()> { SERIAL.lock().unwrap_or_else(|e| e.into_inner()) }

struct DirOps;
impl InodeOps for DirOps {
    /// # C: O(1)
    fn lookup(&self, _i: &Inode, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enoent) }
}

fn dir_inode(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), Arc::new(DirOps),
                      default_file_ops()).build()
}

struct Backend { root_ino: u64 }
impl FileSystem for Backend {
    /// # C: O(1)
    fn name(&self) -> &str { "fanmnt" }
    /// # C: O(1)
    fn magic(&self) -> u64 { 0x0f0f_0f0f }
    /// # C: O(1)
    fn root(&self) -> Option<InodeRef> { Some(dir_inode(self.root_ino)) }
}

/// A `file_system_type` for the compat graft path, which realizes the
/// superblock from the backend itself and never calls `mount`. # C: O(1)
struct Ty;
impl FileSystemType for Ty {
    /// # C: O(1)
    fn name(&self) -> &str { "fanmnt" }
    /// # C: O(1)
    fn mount(&self, _src: Option<&str>, _opts: &str) -> KResult<Arc<SuperBlock>> {
        Err(VfsError::Einval)
    }
}

/// A mountpoint dentry that is not the namespace root, so the graft takes the
/// ordinary submount path rather than the root-install one. # C: O(1)
fn mountpoint(name: &str) -> Arc<Dentry> {
    vfs::dcache::d_alloc_pseudo(name, dir_inode(0x7000), &crate::anon_dname::ANON_INODE_OPS)
}

/// Graft one mount at `d` through the REAL mount API and hand back its id.
/// # C: O(depth)
fn graft(d: &Arc<Dentry>, root_ino: u64) -> u64 {
    let ty: Arc<dyn FileSystemType> = Arc::new(Ty);
    let fs: Arc<dyn FileSystem> = Arc::new(Backend { root_ino });
    vfs::mount::register_typed(ty, Some(d.clone()), fs).expect("graft");
    vfs::mount::mount_at_path_exact(d).expect("mount is in the table").mnt_id
}

/// A `FAN_REPORT_MNT` group with a mount-namespace mark on `ns` for `mask`.
/// # C: O(1)
fn mnt_group(ns: u64, mask: u32) -> Arc<InotifyData> {
    install_mnt_hook();
    let g = InotifyData::new_fanotify(FAN_REPORT_MNT);
    assert_eq!(apply_mark_ns(&g, MarkScope::MountNamespace, 0, 0, ns, mask, true, false, 0), 0);
    g
}

/// Retire a group's mount-namespace mark (removing its whole mask drops the
/// mark), so the process-wide mount-mark count returns to where it started.
/// # C: O(N_watches)
fn drop_mark(g: &Arc<InotifyData>, ns: u64, mask: u32) {
    apply_mark_ns(g, MarkScope::MountNamespace, 0, 0, ns, mask, false, false, 0);
}

/// Drain the group and decode each record as `(mask, fd, mnt_id)`. Every record
/// must be bare metadata plus exactly one mount info record — the only shape a
/// `FAN_REPORT_MNT` group may emit. # C: O(records)
fn read_mnt_records(g: &InotifyData) -> Vec<(u32, i32, u64)> {
    let mut buf = [0u8; 1024];
    let Ok(n) = g.read_fanotify(&mut buf) else { return Vec::new() };
    let mut out = Vec::new();
    let mut off = 0usize;
    while off < n {
        let ev_len = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
        assert_eq!(ev_len, FAN_EVENT_METADATA_LEN + MNT_INFO_LEN,
                   "a mount event is bare metadata plus one mount record");
        let mask = u64::from_le_bytes(buf[off + 8..off + 16].try_into().unwrap()) as u32;
        let fd = i32::from_le_bytes(buf[off + 16..off + 20].try_into().unwrap());
        let r = off + FAN_EVENT_METADATA_LEN;
        assert_eq!(buf[r], FAN_EVENT_INFO_TYPE_MNT);
        assert_eq!(buf[r + 1], 0, "pad byte is zero");
        assert_eq!(u16::from_le_bytes([buf[r + 2], buf[r + 3]]), MNT_INFO_LEN as u16);
        out.push((mask, fd, u64::from_le_bytes(buf[r + 4..r + 12].try_into().unwrap())));
        off += ev_len;
    }
    out
}

/// The records naming one of `ids`, in queue order. # C: O(records)
fn records_for(g: &InotifyData, ids: &[u64]) -> Vec<(u32, i32, u64)> {
    read_mnt_records(g).into_iter().filter(|(_, _, id)| ids.contains(id)).collect()
}

/// THE hook test: a real graft through `vfs::mount` and a real umount produce
/// the attach and the detach, each naming the mount that actually moved. No
/// fire function is called by name here — everything after `register_typed` is
/// the production path.
/// # C: O(1)
#[test]
fn a_real_mount_and_umount_reach_a_mntns_mark() {
    let _s = guard();
    let ns = vfs::mntns::current_namespace().id();
    let g = mnt_group(ns, MNT_EVENTS);

    let d = mountpoint("fanmnt_attach");
    let id = graft(&d, 0xA001);
    assert_eq!(records_for(&g, &[id]), [(FAN_MNT_ATTACH, FAN_NOFD, id)],
               "the attach names the grafted mount and carries no descriptor");

    assert_eq!(vfs::mount::unregister(&d), 1, "umount removed the mount");
    assert_eq!(records_for(&g, &[id]), [(FAN_MNT_DETACH, FAN_NOFD, id)],
               "the detach names the SAME mount that was grafted");
    drop_mark(&g, ns, MNT_EVENTS);
}

/// A mark that asked for only one of the two bits hears that transition and
/// stays silent for the other.
/// # C: O(1)
#[test]
fn a_mark_only_hears_the_transition_it_subscribed_to() {
    let _s = guard();
    let ns = vfs::mntns::current_namespace().id();
    let g = mnt_group(ns, FAN_MNT_DETACH);

    let d = mountpoint("fanmnt_detach_only");
    let id = graft(&d, 0xA002);
    assert!(records_for(&g, &[id]).is_empty(), "the attach was not subscribed to");

    assert_eq!(vfs::mount::unregister(&d), 1);
    assert_eq!(records_for(&g, &[id]), [(FAN_MNT_DETACH, FAN_NOFD, id)]);
    drop_mark(&g, ns, FAN_MNT_DETACH);
}

/// A mark on a DIFFERENT mount namespace hears nothing: the mark's object is
/// the namespace, and a mount-tree change never crosses one.
/// # C: O(1)
#[test]
fn a_mark_on_another_namespace_hears_nothing() {
    let _s = guard();
    let ns = vfs::mntns::current_namespace().id();
    let other = ns.wrapping_add(0x5000_0000);
    let g = mnt_group(other, MNT_EVENTS);

    let d = mountpoint("fanmnt_other_ns");
    let id = graft(&d, 0xA003);
    vfs::mount::unregister(&d);
    assert!(records_for(&g, &[id]).is_empty(), "another namespace's tree is not this mark's");
    drop_mark(&g, other, MNT_EVENTS);
}

/// Two mounts produce two records. Mount events never merge: each names a
/// different mount in its own info record, and a merge keeps one record while
/// OR-ing the masks — the other mount would vanish.
/// # C: O(1)
#[test]
fn two_mount_changes_stay_two_records() {
    let _s = guard();
    let ns = vfs::mntns::current_namespace().id();
    let g = mnt_group(ns, MNT_EVENTS);

    let a = mountpoint("fanmnt_merge_a");
    let b = mountpoint("fanmnt_merge_b");
    let id_a = graft(&a, 0xA004);
    let id_b = graft(&b, 0xA005);
    assert_eq!(records_for(&g, &[id_a, id_b]),
               [(FAN_MNT_ATTACH, FAN_NOFD, id_a), (FAN_MNT_ATTACH, FAN_NOFD, id_b)]);

    vfs::mount::unregister(&b);
    vfs::mount::unregister(&a);
    assert_eq!(records_for(&g, &[id_a, id_b]),
               [(FAN_MNT_DETACH, FAN_NOFD, id_b), (FAN_MNT_DETACH, FAN_NOFD, id_a)]);
    drop_mark(&g, ns, MNT_EVENTS);
}

/// The zero-mark fast path: the counter the mount choke points consult must
/// return to zero when the last mount-namespace mark goes away, whether it was
/// removed or died with its group. A leak makes every mount on the system pay
/// for a watcher that no longer exists.
/// # C: O(1)
#[test]
fn the_last_mntns_mark_leaving_restores_the_fast_path() {
    let _s = guard();
    let ns = vfs::mntns::current_namespace().id();
    let before = MNTNS_MARK_COUNT.load(Ordering::Acquire);

    let g = mnt_group(ns, MNT_EVENTS);
    assert_eq!(MNTNS_MARK_COUNT.load(Ordering::Acquire), before + 1);
    drop_mark(&g, ns, MNT_EVENTS);
    assert_eq!(MNTNS_MARK_COUNT.load(Ordering::Acquire), before);

    let g2 = mnt_group(ns, MNT_EVENTS);
    assert_eq!(MNTNS_MARK_COUNT.load(Ordering::Acquire), before + 1);
    drop(g2);
    assert_eq!(MNTNS_MARK_COUNT.load(Ordering::Acquire), before, "a dying group gives its marks back");
}

/// `FAN_MARK_MNTNS` names a mount-namespace node. A path resolving to anything
/// else names no object the mark could attach to, so the call is rejected
/// rather than establishing a mark on the wrong thing.
/// # C: O(1)
#[test]
fn a_mntns_mark_needs_a_mount_namespace_node() {
    let _s = guard();
    assert_eq!(mnt_ns_from_inode(&dir_inode(0xB001)), None,
               "an ordinary directory is not a mount-namespace node");
    let ns = vfs::mntns::current_namespace();
    assert_eq!(mnt_ns_from_inode(&nscg::proc_ns::mnt_ns_inode(ns.clone())), Some(ns.id()),
               "the nsfs node resolves to the namespace it retains");
}

/// A non-inode mark is administrative: `CAP_SYS_ADMIN` gates mount, filesystem
/// AND mount-namespace scope, and the check sits AFTER the mount-event/scope
/// pairing and BEFORE every remaining mask rule — so an unprivileged caller
/// whose mask is ALSO invalid is told `EPERM`, not `EINVAL`.
/// # C: O(1)
#[test]
fn a_non_inode_mark_needs_sys_admin_before_any_mask_rule() {
    use syscall::errno::Errno;
    let plain = InotifyData::new_fanotify(0);
    // FAN_FS_ERROR on a MOUNT mark is EINVAL when privileged ...
    assert_eq!(validate_fanotify_mark_group(&plain, MarkScope::Mount, FAN_FS_ERROR, 0, true),
               Err(Errno::Einval));
    // ... and EPERM when not: that mask rule is never reached.
    assert_eq!(validate_fanotify_mark_group(&plain, MarkScope::Mount, FAN_FS_ERROR, 0, false),
               Err(Errno::Eperm));
    // Inode scope is the one an unprivileged group may use.
    assert_eq!(validate_fanotify_mark_group(&plain, MarkScope::Inode, FAN_OPEN, 0, false), Ok(()));
    assert_eq!(validate_fanotify_mark_group(&plain, MarkScope::Filesystem, FAN_OPEN, 0, false),
               Err(Errno::Eperm));

    // The scope/report-mode pairing is checked BEFORE the capability: both
    // mismatched pairings are EINVAL even unprivileged.
    assert_eq!(validate_fanotify_mark_group(&plain, MarkScope::MountNamespace, FAN_MNT_ATTACH, 0, false),
               Err(Errno::Einval));
    let mntg = InotifyData::new_fanotify(FAN_REPORT_MNT);
    assert_eq!(validate_fanotify_mark_group(&mntg, MarkScope::Mount, FAN_MNT_ATTACH, 0, false),
               Err(Errno::Einval));
    // The right pairing, unprivileged, is where EPERM finally lands.
    assert_eq!(validate_fanotify_mark_group(&mntg, MarkScope::MountNamespace, FAN_MNT_ATTACH, 0, false),
               Err(Errno::Eperm));
    assert_eq!(validate_fanotify_mark_group(&mntg, MarkScope::MountNamespace, FAN_MNT_ATTACH, 0, true),
               Ok(()));
}

/// A mount-namespace mark matches no inode: the inode dispatch path must never
/// reach it, whatever `inode_key`/`fsid` a file happens to carry.
/// # C: O(1)
#[test]
fn a_mntns_mark_never_matches_a_file_event() {
    let _s = guard();
    let ns = vfs::mntns::current_namespace().id();
    let g = mnt_group(ns, MNT_EVENTS);
    let ino = InodeBuilder::new(0xC001, mk_mode(FileType::Regular, 0o644),
        default_inode_ops(), Arc::new(InotifyFileOps)).fsid(ns).build();
    fire_self(&ino, FAN_MODIFY);
    fire_self(&ino, FAN_OPEN);
    assert!(g.events.lock().is_empty(), "file events never reach a mount-namespace mark");
    drop_mark(&g, ns, MNT_EVENTS);
}

/// The superblock-teardown sweep keys on `fsid`. A mount-namespace mark stores
/// its namespace id in its OWN field, so a dying filesystem whose `st_dev`
/// happens to equal a live namespace id cannot retire that mark.
/// # C: O(1)
#[test]
fn a_dying_filesystem_cannot_retire_a_mount_namespace_mark() {
    let _s = guard();
    let ns = vfs::mntns::current_namespace().id();
    let g = mnt_group(ns, MNT_EVENTS);
    fire_unmount(ns);   // an `st_dev` numerically equal to the namespace id
    assert_eq!(g.watches.lock().len(), 1, "the mount-namespace mark survived");
    drop_mark(&g, ns, MNT_EVENTS);
}

/// The rendered superblock name is not what a mount event reports; the record
/// carries only the mount id, so an unnamed anonymous filesystem is reported
/// exactly as well as a named one.
/// # C: O(1)
#[test]
fn the_record_carries_only_the_mount_id() {
    assert_eq!(String::from(Ty.name()), "fanmnt");
    assert_eq!(MNT_INFO_LEN, 4 + 8, "header plus one 64-bit id, nothing else");
}
