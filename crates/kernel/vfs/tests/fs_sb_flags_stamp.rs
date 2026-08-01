//! `mount(2)`'s `SB_*` word must reach `sb->s_flags`.
//!
//! Linux assigns `s->s_flags = flags` in `alloc_super()` — at superblock
//! ALLOCATION — so:
//!   * a freshly created instance carries every requested `SB_*` bit, and
//!     `SB_RDONLY` and the superblock's read-only predicate agree;
//!   * a `sget()` HIT returns the EXISTING instance untouched, so
//!     `mount -o ro -t proc proc /somewhere-else` can never make an
//!     already-mounted instance read-only behind the first mounter's back.
//!
//! Before this, the classic fill-super boundary dropped the flag word entirely
//! for every filesystem that did not opt into a second, flag-taking constructor
//! form — so `mount -o ro,nosuid,noatime -t tmpfs` produced `s_flags == 0` and
//! every `SB_RDONLY`/`SB_NOATIME` consumer read "unrestricted".
//!
//! SERIAL: the device-backed half registers a superblock on the global
//! `fs_supers` list under a test-unique `s_dev`.

use std::sync::Arc;

use vfs::fs::{superblock_from_filesystem, FileSystem, FsFlags, FsType};
use vfs::superblock::{SB_NOATIME, SB_NODEV, SB_NOSUID, SB_RDONLY};
use vfs::{default_file_ops, default_inode_ops, mk_mode, FileType, InodeBuilder, InodeRef};

const T_MAGIC: u64 = 0x7342_4653; // unique to this test

/// Anonymous-dev backend: `dev_id() == None`, so every realize allocates a
/// fresh superblock (Linux `mount_nodev`).
struct NodevFs;
impl FileSystem for NodevFs {
    fn name(&self) -> &str { "sbflagnodev" }
    fn magic(&self) -> u64 { T_MAGIC }
    fn root(&self) -> Option<InodeRef> {
        Some(InodeBuilder::new(1, mk_mode(FileType::Directory, 0),
            default_inode_ops(), default_file_ops()).build())
    }
}

/// Device-backed backend: a fixed `dev_id()` routes the second realize through
/// `sget()`'s HIT path (Linux `mount_bdev` → `sget` → existing `s_dev`).
struct DevFs(u64);
impl FileSystem for DevFs {
    fn name(&self) -> &str { "sbflagdev" }
    fn magic(&self) -> u64 { T_MAGIC }
    fn dev_id(&self) -> Option<u64> { Some(self.0) }
    fn root(&self) -> Option<InodeRef> {
        Some(InodeBuilder::new(1, mk_mode(FileType::Directory, 0),
            default_inode_ops(), default_file_ops()).build())
    }
}

fn nodev_type() -> Arc<FsType> {
    FsType::new("sbflagnodev", T_MAGIC, FsFlags::empty(),
        Box::new(|ty, _s, _t, _d, sb_flags, _: &[vfs::fs::FsParameter]| {
            let fs: Arc<dyn FileSystem> = Arc::new(NodevFs);
            superblock_from_filesystem(ty, fs, None, String::from("sbflagnodev"), sb_flags)
        }))
}

#[test]
fn a_new_superblock_carries_the_requested_sb_flags() {
    let ty = nodev_type();
    let want = SB_RDONLY | SB_NOATIME | SB_NOSUID | SB_NODEV;
    let sb = ty.construct_with_flags(None, "/mnt", "", want).expect("realize");
    assert_eq!(sb.s_flags() & want, want,
        "mount -o ro,noatime,nosuid,nodev must land in s_flags");
    assert!(sb.is_readonly(), "SB_RDONLY and the read-only predicate must agree");
}

#[test]
fn an_unflagged_mount_leaves_the_user_bits_clear() {
    let ty = nodev_type();
    let sb = ty.construct(None, "/mnt", "").expect("realize");
    assert_eq!(sb.s_flags() & (SB_RDONLY | SB_NOATIME | SB_NOSUID | SB_NODEV), 0);
    assert!(!sb.is_readonly());
}

#[test]
fn an_sget_hit_keeps_the_live_instances_flags() {
    // Both realizes name the same `s_dev`, so the second is Linux's `sget()`
    // HIT: it returns the FIRST superblock, whose flags were fixed at
    // `alloc_super()` time and are not re-stamped by a later mounter.
    const DEV: u64 = 0x5342_0001;
    let ty = FsType::new("sbflagdev", T_MAGIC, FsFlags::empty(),
        Box::new(|ty, _s, _t, _d, sb_flags, _: &[vfs::fs::FsParameter]| {
            let fs: Arc<dyn FileSystem> = Arc::new(DevFs(DEV));
            superblock_from_filesystem(ty, fs, None, String::from("sbflagdev"), sb_flags)
        }));
    let first = ty.construct_with_flags(None, "/mnt", "", 0).expect("first realize");
    assert!(!first.is_readonly(), "first mount was read-write");

    // A hit whose read-only state AGREES shares the instance, and the other
    // `SB_*` bits it asked for are not stamped onto it — those are per-mount
    // and ride the mount, not the superblock.
    let second = ty.construct_with_flags(None, "/mnt2", "", SB_NOATIME)
        .expect("second realize");
    assert!(Arc::ptr_eq(&first, &second), "same s_dev must reuse the instance");
    assert_eq!(second.s_flags() & SB_NOATIME, 0,
        "an sget hit must not re-stamp any SB_* bit on the live instance");
}

// FAILS-BEFORE: this second mount SUCCEEDED and silently flipped the live
// instance read-only under every task already holding a writable file on it.
#[test]
fn an_sget_hit_that_would_change_the_read_only_state_is_refused() {
    const DEV: u64 = 0x5342_0002;
    let ty = FsType::new("sbflagro", T_MAGIC, FsFlags::empty(),
        Box::new(|ty, _s, _t, _d, sb_flags, _: &[vfs::fs::FsParameter]| {
            let fs: Arc<dyn FileSystem> = Arc::new(DevFs(DEV));
            superblock_from_filesystem(ty, fs, None, String::from("sbflagro"), sb_flags)
        }));
    let rw = ty.construct_with_flags(None, "/mnt", "", 0).expect("first realize");
    assert!(!rw.is_readonly());

    let refused = ty.construct_with_flags(None, "/mnt2", "", SB_RDONLY).err();
    assert_eq!(refused, Some(vfs::VfsError::Ebusy),
        "mounting the same device read-only over a read-write instance");
    assert!(!rw.is_readonly(), "the live instance kept the state its own mount chose");

    // The refusal is specific to the read-only bit and specific to REUSE: the
    // same request against a fresh device still creates a read-only instance.
    let ro_ty = FsType::new("sbflagro2", T_MAGIC, FsFlags::empty(),
        Box::new(|ty, _s, _t, _d, sb_flags, _: &[vfs::fs::FsParameter]| {
            let fs: Arc<dyn FileSystem> = Arc::new(DevFs(0x5342_0003));
            superblock_from_filesystem(ty, fs, None, String::from("sbflagro2"), sb_flags)
        }));
    let ro = ro_ty.construct_with_flags(None, "/mnt3", "", SB_RDONLY).expect("fresh read-only");
    assert!(ro.is_readonly());
}
