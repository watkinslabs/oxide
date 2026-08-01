//! `touch_atime` / `file_accessed` PLUMBING (Linux fs/inode.c `touch_atime`,
//! include/linux/fs.h `file_accessed`). The pure decision ladder is covered by
//! `inode_atime_policy.rs`; this file proves the ladder is actually WIRED — a
//! live inode + a live mount, and the timestamp really moves (or really does
//! not) through `i_op->update_time(S_ATIME)`.
//!
//! Before F775 `AtimePolicy`/`atime_needs_update` had ZERO call sites in the
//! tree, so `read`, `getdents`, `readlink` and `mmap` never advanced any
//! inode's access time at all.

use std::sync::{Arc, Mutex, MutexGuard};

use vfs::atime::{atime_ctx, file_type_tracks_atime, mnt_flags_for, touch_atime, touch_atime_needed};
use vfs::inode::Inode;
use vfs::inode_times::{AtimeCtx, RELATIME_MAX_AGE_SECS};
use vfs::fs::FileSystem;
use vfs::mount::{
    MNT_NOATIME, MNT_NODIRATIME, MNT_RDONLY, MNT_RELATIME, MNT_STRICTATIME,
    MS_NOATIME, MS_NODIRATIME, MS_RDONLY, MS_STRICTATIME,
};
use vfs::superblock::SB_RDONLY;
use vfs::{
    default_file_ops, mk_mode, FileType, InodeBuilder, InodeOps, InodeRef, KResult, S_NOATIME,
    Timespec64, VfsError,
};

mod common;

static SERIAL: Mutex<()> = Mutex::new(());

/// Fixed wall clock the whole file shares. Well past the 24h relatime window so
/// a "stale atime" case is expressible without negative seconds.
const NOW_SEC: i64 = 1_700_000_000;
fn now_ns() -> u64 { (NOW_SEC as u64) * 1_000_000_000 }
fn ts(sec: i64) -> Timespec64 { Timespec64::from_secs(sec) }

fn guard() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    vfs::mount::set_current_ns_provider(common::current_namespace);
    common::install();
    // The wall clock the atime stamp reads. Without it `touch_atime` is a no-op
    // by design (early boot), which is itself asserted below.
    vfs::inode_times::set_realtime_provider(now_ns);
    g
}

struct TFs { root_ino: u64 }
impl FileSystem for TFs {
    fn name(&self) -> &str { "atimefs" }
    fn root(&self) -> Option<InodeRef> { Some(make_dir(self.root_ino)) }
}
struct TDirOps;
impl InodeOps for TDirOps {
    fn lookup(&self, _inode: &Inode, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enoent) }
}
fn make_dir(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), Arc::new(TDirOps), default_file_ops()).build()
}
fn fs(ino: u64) -> Arc<dyn FileSystem> { Arc::new(TFs { root_ino: ino }) }

/// A standalone inode with explicit times. `ft` picks regular vs directory so
/// the NODIRATIME arms are reachable.
fn inode_with(ft: FileType, atime: i64, mtime: i64, ctime: i64) -> InodeRef {
    InodeBuilder::new(0x2000, mk_mode(ft, 0o644), Arc::new(TDirOps), default_file_ops())
        .times(ts(atime), ts(mtime), ts(ctime))
        .build()
}

/// Mount `atimefs` at `/m` with the given mount(2) MS_* request mask and return
/// its `mnt_id`. Every test re-registers so the flags are exact.
fn mount_with(path: &str, fsid: u64, ms: u64) -> u64 {
    common::register("/", fs(0x1)).ok();
    common::register(path, fs(fsid)).expect("mount");
    if ms != 0 {
        let d = common::dentry(path);
        vfs::mount::remount_flags(&d, ms).expect("remount");
    }
    common::mount_at_path_exact(path).expect("mount exists").mnt_id
}

// ---------------------------------------------------------------- decision --

// The mount-RO gate Linux spells `mnt_get_write_access(mnt)`: it is DISJOINT
// from SB_RDONLY, so a read-only BIND over a writable superblock must still
// refuse the atime advance. `atime_needs_update` alone does not see it.
#[test]
fn read_only_mount_blocks_atime_even_with_a_writable_superblock() {
    let c = AtimeCtx {
        mnt_flags: MNT_RELATIME | MNT_RDONLY, sb_flags: 0, inode_noatime: false,
        is_dir: false, atime: ts(100), mtime: ts(200), ctime: ts(200),
    };
    // mtime >= atime, so the relatime ladder itself says YES.
    assert!(vfs::inode_times::atime_needs_update(&c, ts(NOW_SEC)),
        "precondition: the relatime ladder wants the update");
    assert!(!touch_atime_needed(&c, ts(NOW_SEC)),
        "MNT_RDONLY denies write access, so touch_atime skips the stamp");
    let mut w = c; w.mnt_flags = MNT_RELATIME;
    assert!(touch_atime_needed(&w, ts(NOW_SEC)), "a writable mount takes it");
}

// A read-only SUPERBLOCK is the other half and is already inside the ladder;
// pin both so a future refactor cannot drop one.
#[test]
fn read_only_superblock_blocks_atime() {
    let c = AtimeCtx {
        mnt_flags: MNT_STRICTATIME, sb_flags: SB_RDONLY, inode_noatime: false,
        is_dir: false, atime: ts(100), mtime: ts(200), ctime: ts(200),
    };
    assert!(!touch_atime_needed(&c, ts(NOW_SEC)));
}

// Linux `touch_atime` carries NO `IS_IMMUTABLE` test — immutability forbids a
// CALLER's mutation, not the kernel's own access-time bookkeeping. An immutable
// file still advances atime on read.
#[test]
fn an_immutable_inode_still_advances_atime() {
    let _g = guard();
    let mnt = mount_with("/imm", 0xA1, 0);
    let ino = inode_with(FileType::Regular, NOW_SEC - 10_000, NOW_SEC - 5, NOW_SEC - 5);
    ino.set_i_flags(ino.i_flags() | vfs::S_IMMUTABLE);
    let before = ino.atime().unwrap();
    touch_atime(mnt, &ino);
    assert_ne!(ino.atime().unwrap(), before,
        "S_IMMUTABLE is not an atime gate in Linux touch_atime");
}

// The per-inode chattr bit IS a gate, and it wins over strictatime.
#[test]
fn per_inode_s_noatime_blocks_the_stamp() {
    let _g = guard();
    let mnt = mount_with("/sn", 0xA2, MS_STRICTATIME);
    let ino = inode_with(FileType::Regular, NOW_SEC - 10_000, NOW_SEC - 5, NOW_SEC - 5);
    ino.set_i_flags(ino.i_flags() | S_NOATIME);
    let before = ino.atime().unwrap();
    touch_atime(mnt, &ino);
    assert_eq!(ino.atime().unwrap(), before, "S_NOATIME short-circuits touch_atime");
}

// ------------------------------------------------------- relatime, for real --

// relatime edge 1: atime already ahead of mtime/ctime and younger than a day →
// no stamp. This is the case that makes relatime cheap, and the one an ordinal
// "always update" implementation would get wrong on every read.
#[test]
fn relatime_leaves_a_fresh_atime_alone() {
    let _g = guard();
    let mnt = mount_with("/r1", 0xA3, 0); // default == relatime
    assert_eq!(mnt_flags_for(mnt) & MNT_RELATIME, MNT_RELATIME, "default mount is relatime");
    let ino = inode_with(FileType::Regular, NOW_SEC - 60, NOW_SEC - 600, NOW_SEC - 600);
    let before = ino.atime().unwrap();
    touch_atime(mnt, &ino);
    assert_eq!(ino.atime().unwrap(), before, "atime newer than mtime/ctime and < 24h old");
}

// relatime edge 2: mtime caught up with atime (the file was written since the
// last read) → the next read stamps.
#[test]
fn relatime_stamps_when_the_file_was_modified_since_the_last_read() {
    let _g = guard();
    let mnt = mount_with("/r2", 0xA4, 0);
    let ino = inode_with(FileType::Regular, NOW_SEC - 600, NOW_SEC - 600, NOW_SEC - 600);
    touch_atime(mnt, &ino);
    assert_eq!(ino.atime().unwrap(), ts(NOW_SEC), "mtime >= atime forces the update");
}

// relatime edge 3: exactly the 24h boundary. `>= 24*60*60` seconds, compared in
// WHOLE seconds — one second under the window must NOT stamp.
#[test]
fn relatime_twenty_four_hour_boundary_is_inclusive() {
    let _g = guard();
    let mnt = mount_with("/r3", 0xA5, 0);

    let stale = inode_with(FileType::Regular, NOW_SEC - RELATIME_MAX_AGE_SECS, NOW_SEC - 999_999, NOW_SEC - 999_999);
    touch_atime(mnt, &stale);
    assert_eq!(stale.atime().unwrap(), ts(NOW_SEC), "exactly 24h stale stamps");

    let fresh = inode_with(FileType::Regular, NOW_SEC - RELATIME_MAX_AGE_SECS + 1, NOW_SEC - 999_999, NOW_SEC - 999_999);
    let before = fresh.atime().unwrap();
    touch_atime(mnt, &fresh);
    assert_eq!(fresh.atime().unwrap(), before, "one second under 24h does not");
}

// ------------------------------------------------------------ mount policy --

#[test]
fn noatime_mount_never_stamps() {
    let _g = guard();
    let mnt = mount_with("/na", 0xA6, MS_NOATIME);
    assert_ne!(mnt_flags_for(mnt) & MNT_NOATIME, 0, "MS_NOATIME maps to MNT_NOATIME");
    let ino = inode_with(FileType::Regular, NOW_SEC - 999_999, NOW_SEC - 5, NOW_SEC - 5);
    let before = ino.atime().unwrap();
    touch_atime(mnt, &ino);
    assert_eq!(ino.atime().unwrap(), before);
}

#[test]
fn nodiratime_mount_stops_directories_but_not_files() {
    let _g = guard();
    let mnt = mount_with("/nd", 0xA7, MS_NODIRATIME);
    assert_ne!(mnt_flags_for(mnt) & MNT_NODIRATIME, 0);

    let dir = inode_with(FileType::Directory, NOW_SEC - 999_999, NOW_SEC - 5, NOW_SEC - 5);
    let dir_before = dir.atime().unwrap();
    touch_atime(mnt, &dir);
    assert_eq!(dir.atime().unwrap(), dir_before, "MNT_NODIRATIME suppresses directory atime");

    let reg = inode_with(FileType::Regular, NOW_SEC - 999_999, NOW_SEC - 5, NOW_SEC - 5);
    touch_atime(mnt, &reg);
    assert_eq!(reg.atime().unwrap(), ts(NOW_SEC), "regular files still stamp");
}

#[test]
fn strictatime_stamps_a_fresh_atime_that_relatime_would_skip() {
    let _g = guard();
    let strict = mount_with("/sa", 0xA8, MS_STRICTATIME);
    let rel = mount_with("/re", 0xA9, 0);

    let a = inode_with(FileType::Regular, NOW_SEC - 60, NOW_SEC - 600, NOW_SEC - 600);
    touch_atime(rel, &a);
    assert_eq!(a.atime().unwrap(), ts(NOW_SEC - 60), "relatime skips this one");

    let b = inode_with(FileType::Regular, NOW_SEC - 60, NOW_SEC - 600, NOW_SEC - 600);
    touch_atime(strict, &b);
    assert_eq!(b.atime().unwrap(), ts(NOW_SEC), "strictatime stamps it");
}

#[test]
fn a_read_only_mount_never_stamps_end_to_end() {
    let _g = guard();
    let mnt = mount_with("/ro", 0xAA, MS_RDONLY);
    assert_ne!(mnt_flags_for(mnt) & MNT_RDONLY, 0);
    let ino = inode_with(FileType::Regular, NOW_SEC - 999_999, NOW_SEC - 5, NOW_SEC - 5);
    let before = ino.atime().unwrap();
    touch_atime(mnt, &ino);
    assert_eq!(ino.atime().unwrap(), before);
}

// ---------------------------------------------------------------- plumbing --

// An anon description (pipe/socket/memfd, `mnt_id == 0`) has no vfsmount.
// Linux's internal `kern_mount` vfsmounts carry `mnt_flags == 0`, i.e.
// strictatime, so a pipe read stamps every time.
#[test]
fn an_anon_description_resolves_to_strictatime_not_noatime() {
    let _g = guard();
    assert_eq!(mnt_flags_for(0), 0, "no vfsmount → mnt_flags 0 → strictatime");
    let ino = inode_with(FileType::Fifo, NOW_SEC - 1, NOW_SEC - 600, NOW_SEC - 600);
    touch_atime(0, &ino);
    assert_eq!(ino.atime().unwrap(), ts(NOW_SEC));
}

// The set of file types whose read path Linux runs `file_accessed` on. Sockets
// and character devices have no generic read helper and never stamp; oxide
// funnels both through the same `File::read`, so the set is explicit.
#[test]
fn only_the_linux_file_accessed_types_track_atime() {
    for ft in [FileType::Regular, FileType::BlockDev, FileType::Fifo, FileType::Directory] {
        assert!(file_type_tracks_atime(ft), "{ft:?} has a generic read helper in Linux");
    }
    for ft in [FileType::Socket, FileType::CharDev] {
        assert!(!file_type_tracks_atime(ft), "{ft:?} never reaches file_accessed in Linux");
    }
    // Symlinks never reach `file_accessed` (they cannot be opened for read);
    // their atime comes from `touch_atime` in readlink / get_link instead.
    assert!(!file_type_tracks_atime(FileType::Symlink));
}

// The context snapshot must read the LIVE inode, not a stale copy: this is what
// made the pre-F775 policy untestable end-to-end.
#[test]
fn the_context_snapshot_tracks_the_live_inode() {
    let _g = guard();
    let ino = inode_with(FileType::Directory, 10, 20, 30);
    let c = atime_ctx(MNT_RELATIME, &ino);
    assert_eq!((c.atime, c.mtime, c.ctime), (ts(10), ts(20), ts(30)));
    assert!(c.is_dir, "a directory inode sets the NODIRATIME-gating flag");
    assert!(!c.inode_noatime);
    ino.set_i_flags(ino.i_flags() | S_NOATIME);
    assert!(atime_ctx(MNT_RELATIME, &ino).inode_noatime, "re-snapshot sees the new flag");
}

// Before the wall clock exists there is no timestamp to write. Stamping here
// would set every early-boot inode's atime to the epoch and — on a backend that
// persists through `update_time` — write that to disk.
#[test]
fn no_wall_clock_installed_means_no_stamp() {
    let _g = guard();
    vfs::inode_times::set_realtime_provider(|| 0);
    let mnt = mount_with("/nc", 0xAB, MS_STRICTATIME);
    let ino = inode_with(FileType::Regular, 1, 2, 3);
    touch_atime(mnt, &ino);
    assert_eq!(ino.atime().unwrap(), ts(1), "epoch-0 clock is not a timestamp");
    vfs::inode_times::set_realtime_provider(now_ns);
}

// A second touch inside the same clock tick must not re-write (Linux's
// `timespec64_equal(&atime, &now)` short-circuit) — otherwise every read of a
// strictatime mount would dirty the inode again.
#[test]
fn a_repeat_touch_in_the_same_tick_is_a_no_op() {
    let _g = guard();
    let mnt = mount_with("/rp", 0xAC, MS_STRICTATIME);
    let ino = inode_with(FileType::Regular, NOW_SEC - 900, NOW_SEC - 900, NOW_SEC - 900);
    touch_atime(mnt, &ino);
    assert_eq!(ino.atime().unwrap(), ts(NOW_SEC));
    let ctime_after_first = ino.ctime().unwrap();
    touch_atime(mnt, &ino);
    assert_eq!(ino.atime().unwrap(), ts(NOW_SEC));
    assert_eq!(ino.ctime().unwrap(), ctime_after_first,
        "an atime-only update never moves ctime");
}
