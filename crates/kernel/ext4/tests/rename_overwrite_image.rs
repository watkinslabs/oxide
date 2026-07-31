//! P7b rename-overwrite nlink authority: a plain rename that OVERWRITES an
//! existing destination must drop the replaced target's in-memory `st_nlink`
//! (Linux `vfs_rename`), mirroring the unlink path's authority now that the
//! dcache `d_unlink` no longer touches nlink. RENAME_EXCHANGE must NOT drop —
//! both inodes survive.
//!
//! Image: mini.img (root dir = inode 2, no journal). We create two regular
//! files in the root, hold the cached `Arc` for the destination, rename the
//! source over it, and assert the replaced inode's nlink dropped to 0.

extern crate alloc;
mod common;
use alloc::string::String;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::fs::FileSystem;
use vfs::{CreateCtx, FileType, SuperBlock};

const MINI: &[u8] = include_bytes!("mini.img");
const BLOCK_SIZE: u32 = 512;

fn disk() -> Arc<dyn BlockDevice> {
    let cap = (MINI.len() as u64) / (BLOCK_SIZE as u64);
    let d: Arc<MemDisk<TaskList>> = MemDisk::new(BLOCK_SIZE, cap);
    let mut req = BlockRequest { op: BlockOp::Write, start_block: 0, len_blocks: cap as u32, buffer: MINI.to_vec(), ..Default::default() };
    d.submit_sync(&mut req).expect("memdisk write");
    d
}

/// Open the fixture as an `Ext4Mount` and back-stamp a live `SuperBlock` so
/// inode lookups populate the per-SB icache (the `ilookup` rename relies on).
fn mount() -> (Arc<ext4::rootfs::Ext4Mount>, Arc<SuperBlock>) {
    let m = ext4::rootfs::Ext4Mount::open(disk()).expect("Ext4Mount::open");
    let fs: Arc<dyn FileSystem> = m.clone();
    let root = fs.root();
    let sb = common::realize_sb(fs, root, 0xE471_0001, String::from("ext4"));
    (m, sb)
}

#[test]
fn rename_overwrite_drops_replaced_target_nlink() {
    let (m, sb) = mount();
    let root = sb.s_root_inode().expect("root inode");
    let _src = root.create_child("rsrc", 0o644, &CreateCtx::root()).expect("create rsrc");
    let dst = root.create_child("rdst", 0o644, &CreateCtx::root()).expect("create rdst");
    assert_eq!(dst.nlink(), 1, "fresh dest starts with one link");

    m.state().rename_at(b"/rsrc", b"/rdst").expect("rename overwrite");

    // The replaced (cached) destination inode lost its link.
    assert_eq!(dst.nlink(), 0, "replaced destination in-memory nlink dropped to 0");
    // Source name gone; destination name now resolves on disk.
    assert!(m.state().lookup_path(b"/rsrc").is_none(), "source name removed");
    assert!(m.state().lookup_path(b"/rdst").is_some(), "destination name present");
}

#[test]
fn iop_rename_overwrite_drops_replaced_target_nlink() {
    // D9: the resolved-parent `i_op->rename` is byte-equivalent to the
    // backend rename path — same overwrite + nlink-drop semantics.
    let (m, sb) = mount();
    let root = sb.s_root_inode().expect("root inode");
    let src = root.create_child("isrc", 0o644, &CreateCtx::root()).expect("create isrc");
    let dst = root.create_child("idst", 0o644, &CreateCtx::root()).expect("create idst");
    assert_eq!(dst.nlink(), 1);

    root.rename_child("isrc", &root, "idst", 0, &CreateCtx::root()).expect("iop rename overwrite");

    assert_eq!(dst.nlink(), 0, "replaced destination in-memory nlink dropped to 0");
    assert!(m.state().lookup_path(b"/isrc").is_none(), "source name removed");
    let now = root.lookup("idst").expect("idst present");
    assert!(Arc::ptr_eq(&now, &src), "destination name now holds the source inode");
}

#[test]
fn iop_rename_handles_exchange_whiteout() {
    let (_m, sb) = mount();
    let root = sb.s_root_inode().expect("root inode");
    root.create_child("ix", 0o644, &CreateCtx::root()).expect("create ix");
    root.create_child("iy", 0o644, &CreateCtx::root()).expect("create iy");
    let ix = root.lookup("ix").expect("ix lookup");
    let iy = root.lookup("iy").expect("iy lookup");

    root.rename_child("ix", &root, "iy", vfs::namei::RENAME_EXCHANGE, &CreateCtx::root()).expect("exchange");
    assert_eq!(root.lookup("ix").unwrap().ino(), iy.ino(), "ix now names old iy");
    assert_eq!(root.lookup("iy").unwrap().ino(), ix.ino(), "iy now names old ix");

    root.rename_child("iy", &root, "iz", vfs::namei::RENAME_WHITEOUT, &CreateCtx::root()).expect("whiteout");
    assert_eq!(root.lookup("iz").unwrap().ino(), ix.ino(), "iz now names moved source");
    assert_eq!(root.lookup("iy").unwrap().file_type(), FileType::CharDev, "source became whiteout");
}

#[test]
fn iop_link_child_hardlinks_and_bumps_nlink() {
    // D9/D13: the resolved-parent `i_op->link` is the path link(2)/linkat(2)
    // now take — it journals a `dir_link` for the existing inode under a new
    // name in the parent dir, bumps the inode's in-memory nlink, and the alias
    // resolves on disk to the same ino. EEXIST on a taken name; EPERM on a dir.
    let (m, sb) = mount();
    let root = sb.s_root_inode().expect("root inode");
    let f = root.create_child("lsrc", 0o644, &CreateCtx::root()).expect("create lsrc");
    assert_eq!(f.nlink(), 1);
    let src_ino = f.ino();

    root.link_child(&f, "lalias", &CreateCtx::root()).expect("iop link");

    assert_eq!(f.nlink(), 2, "hardlink bumped in-memory nlink");
    let alias = root.lookup("lalias").expect("alias resolves");
    assert_eq!(alias.ino(), src_ino, "alias is the SAME on-disk inode");
    assert!(m.state().lookup_path(b"/lalias").is_some(), "alias name present on disk");
    assert!(m.state().lookup_path(b"/lsrc").is_some(), "original name still present");

    // EEXIST on a taken name.
    assert!(matches!(root.link_child(&f, "lalias", &CreateCtx::root()), Err(vfs::VfsError::Eexist)));
    // EPERM on a directory source (no fs permits directory hardlinks).
    let d = root.mkdir("ldir", 0o755, &CreateCtx::root()).expect("mkdir ldir");
    assert!(matches!(root.link_child(&d, "dlink", &CreateCtx::root()), Err(vfs::VfsError::Eperm)));
}

#[test]
fn tmpfile_publish_over_existing_destination() {
    // systemd-hwdb writes an O_TMPFILE, chmods it, links it under a temporary
    // name through /proc/self/fd, then atomically renames it over hwdb.bin.
    let (m, sb) = mount();
    let root = sb.s_root_inode().expect("root inode");
    let old = root.create_child("hwdb.bin", 0o644, &CreateCtx::root()).expect("create old hwdb");
    let tmp = root.tmpfile(0o640, &CreateCtx::root()).expect("create anonymous hwdb");
    let tmp_ino = tmp.ino();
    assert_eq!(tmp.nlink(), 0, "anonymous inode starts unlinked");

    tmp.set_state(vfs::I_LINKABLE, 0);
    tmp.setattr(&vfs::IDENTITY, &vfs::Iattr {
        valid: vfs::ATTR_MODE,
        mode: 0o444,
        ..Default::default()
    }).expect("chmod anonymous hwdb");
    m.state().mount.write_at(tmp_ino as u32, 0, b"oxide-hwdb").expect("write anonymous hwdb");

    root.link_child(&tmp, ".#hwdb.tmp", &CreateCtx::root()).expect("publish temporary link");
    assert_eq!(tmp.nlink(), 1, "published tmpfile has one link");
    root.rename_child(".#hwdb.tmp", &root, "hwdb.bin", 0, &CreateCtx::root()).expect("replace hwdb atomically");

    assert_eq!(old.nlink(), 0, "replaced hwdb was unlinked");
    assert_eq!(tmp.nlink(), 1, "published hwdb retains one link");
    assert_eq!(root.lookup("hwdb.bin").expect("new hwdb lookup").ino(), tmp_ino);
    assert!(matches!(root.lookup(".#hwdb.tmp"), Err(vfs::VfsError::Enoent)));
    assert_eq!(m.state().read_file(b"/hwdb.bin").expect("read new hwdb"), b"oxide-hwdb");
}

#[test]
fn rootfs_path_helpers_return_namei_errnos() {
    let (m, _sb) = mount();
    let st = m.state();

    st.mkdir_at(b"/errdir", 0o755).expect("mkdir errdir");
    assert!(matches!(st.mkdir_at(b"/errdir", 0o755), Err(vfs::VfsError::Eexist)));
    assert!(matches!(st.symlink_at(b"x", b"/errdir"), Err(vfs::VfsError::Eexist)));
    assert!(matches!(st.mknod_at(b"/errdir", vfs::S_IFIFO as u16 | 0o600, 0), Err(vfs::VfsError::Eexist)));
    assert!(matches!(st.unlink_at(b"/errdir"), Err(vfs::VfsError::Eisdir)));

    st.create_at(b"/errfile", 0o644).expect("create errfile");
    assert!(matches!(st.rmdir_at(b"/errfile"), Err(vfs::VfsError::Enotdir)));
    assert!(matches!(st.unlink_at(b"/missing"), Err(vfs::VfsError::Enoent)));
    assert!(matches!(st.link_at(b"/errfile", b"/errdir"), Err(vfs::VfsError::Eexist)));
}

#[test]
fn exchange_does_not_drop_either_nlink() {
    let (m, sb) = mount();
    let root = sb.s_root_inode().expect("root inode");
    let a = root.create_child("xa", 0o644, &CreateCtx::root()).expect("create xa");
    let b = root.create_child("xb", 0o644, &CreateCtx::root()).expect("create xb");
    assert_eq!((a.nlink(), b.nlink()), (1, 1));

    m.state().exchange_at(b"/xa", b"/xb").expect("exchange");

    // Neither inode lost a link: RENAME_EXCHANGE only swaps names.
    assert_eq!(a.nlink(), 1, "exchange survivor a keeps its link");
    assert_eq!(b.nlink(), 1, "exchange survivor b keeps its link");
    assert!(m.state().lookup_path(b"/xa").is_some(), "name xa still present");
    assert!(m.state().lookup_path(b"/xb").is_some(), "name xb still present");
}

#[test]
fn iop_create_reused_ino_rebuilds_cached_type() {
    // GNOME/systemd PrivateTmp churn creates and removes many short-lived ext4
    // names. If ext4 reuses an inode number while a stale VFS inode is still
    // cached, i_op->mkdir must evict that slot before wrapping the new on-disk
    // directory. Otherwise namei sees the new private-tmp parent as a regular
    // file and the next component returns ENOTDIR.
    let (_m, sb) = mount();
    let root = sb.s_root_inode().expect("root inode");
    let stale_file = root.create_child("reuse", 0o644, &CreateCtx::root()).expect("create file");
    let stale_ino = stale_file.ino();
    assert_eq!(stale_file.file_type(), FileType::Regular);

    // Identity handle only — `Arc::clone` is not a counted `i_count` reference.
    let stale_alias = stale_file.clone();

    root.unlink_child("reuse").expect("unlink file");
    // The inode outlives the name for as long as a reference is held (POSIX
    // unlink-while-open), so the ino is NOT reusable yet.
    assert_eq!(stale_file.nlink(), 0, "name gone, inode still alive");
    // Dropping the last reference is what runs `ext4_evict_inode` and returns
    // the inode number to the allocator.
    vfs::file::iput(stale_file);
    let new_dir = root.mkdir("reuse", 0o755, &CreateCtx::root()).expect("mkdir reused name");

    assert_eq!(new_dir.ino(), stale_ino, "fixture reused the freed inode number");
    assert_eq!(new_dir.file_type(), FileType::Directory, "reused inode was rebuilt from disk type");
    assert!(!Arc::ptr_eq(&new_dir, &stale_alias), "mkdir did not return stale regular-file Arc");
}
