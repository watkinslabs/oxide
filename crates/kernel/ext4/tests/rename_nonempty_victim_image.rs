//! F740: `rename(srcdir, dstdir)` where `dstdir` is NOT empty must fail with
//! ENOTEMPTY (Linux `ext4_rename`: `if (!ext4_empty_dir(new.inode)) return
//! -ENOTEMPTY`) and leave BOTH trees untouched.
//!
//! Before F740 the ext4 `i_op->rename` handed a directory victim straight to
//! `Mount::rmdir`, whose documented contract is "remove the CALLER-VERIFIED-
//! EMPTY directory": it truncated the victim's data blocks, cleared its inode
//! and freed the inode bit while the victim's children were still linked to
//! it — silent, unrecoverable loss of the destination subtree on a call Linux
//! rejects outright.
//!
//! Image: mini-j.img (journaled).

extern crate alloc;
mod common;
use alloc::string::String;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::fs::FileSystem;
use vfs::{SuperBlock, VfsError};

const IMAGE: &[u8] = include_bytes!("mini-j.img");
const SECTOR: u32 = 512;
const ROOT: u32 = 2;

fn shared_disk() -> Arc<dyn BlockDevice> {
    let cap = (IMAGE.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest {
        op: BlockOp::Write, start_block: 0, len_blocks: cap as u32, buffer: IMAGE.to_vec(),
    };
    disk.submit_sync(&mut req).expect("seed memdisk");
    disk
}

fn mount(disk: Arc<dyn BlockDevice>) -> (Arc<ext4::rootfs::Ext4Mount>, Arc<SuperBlock>) {
    let m = ext4::rootfs::Ext4Mount::open(disk).expect("Ext4Mount::open");
    let fs: Arc<dyn FileSystem> = m.clone();
    let root = fs.root();
    let sb = common::realize_sb(fs, root, 0xE471_D07D, String::from("ext4"));
    (m, sb)
}

#[test]
fn rename_dir_onto_nonempty_dir_is_enotempty_and_preserves_both() {
    let disk = shared_disk();
    let (m, sb) = mount(disk.clone());
    let src = m.state().mount.create_dir(ROOT, b"src", 0o755, 0, 0).expect("mkdir src");
    let dst = m.state().mount.create_dir(ROOT, b"dst", 0o755, 0, 0).expect("mkdir dst");
    let keep = m.state().mount.create_dir(dst, b"keep", 0o755, 0, 0).expect("mkdir dst/keep");
    let free_inodes = m.state().mount.state_free_inodes();

    assert_eq!(m.state().rename_at(b"/src", b"/dst"), Err(VfsError::Enotempty),
               "a populated destination directory must be refused");

    assert!(m.state().mount.lookup_path(b"/src").is_ok(), "source survives the refusal");
    assert_eq!(m.state().mount.lookup_path(b"/dst"), Ok(dst), "destination survives");
    assert_eq!(m.state().mount.lookup_path(b"/dst/keep"), Ok(keep),
               "the destination's child is still reachable — nothing was freed");
    assert_eq!(m.state().mount.state_free_inodes(), free_inodes,
               "no inode was freed by the refused rename");

    // The victim's inode is intact (not cleared / dtime-stamped).
    let dst_raw = m.state().mount.read_inode(dst).expect("dst inode readable");
    assert!(dst_raw.is_dir() && dst_raw.links_count >= 2, "dst still a live directory");

    drop(sb); drop(m);
    let (m2, _sb2) = mount(disk);
    assert_eq!(m2.state().mount.lookup_path(b"/dst/keep"), Ok(keep),
               "remount: the destination subtree is still on disk");
    assert!(m2.state().mount.lookup_path(b"/src").is_ok(), "remount: source still there");
}

#[test]
fn rename_dir_onto_empty_dir_succeeds_and_balances_parent_nlink() {
    let disk = shared_disk();
    let (m, _sb) = mount(disk);
    let a = m.state().mount.create_dir(ROOT, b"a", 0o755, 0, 0).expect("mkdir a");
    let _b = m.state().mount.create_dir(ROOT, b"b", 0o755, 0, 0).expect("mkdir b");
    let root_nl0 = m.state().mount.read_inode(ROOT).unwrap().links_count;

    m.state().rename_at(b"/a", b"/b").expect("dir onto EMPTY dir is allowed");

    assert_eq!(m.state().mount.lookup_path(b"/b"), Ok(a), "b now names the moved inode");
    assert!(m.state().mount.lookup_path(b"/a").is_err(), "a is gone");
    // The vacated victim's `..` left the root; the moved directory's `..` never
    // moved parent, so the root nets exactly one lost back-reference.
    assert_eq!(m.state().mount.read_inode(ROOT).unwrap().links_count, root_nl0 - 1,
               "root loses exactly the replaced directory's back-reference");
}

#[test]
fn rename_file_onto_nonempty_dir_is_still_refused_at_the_backend() {
    let disk = shared_disk();
    let (m, _sb) = mount(disk);
    let dst = m.state().mount.create_dir(ROOT, b"d", 0o755, 0, 0).expect("mkdir d");
    m.state().mount.create_dir(dst, b"child", 0o755, 0, 0).expect("mkdir d/child");
    m.state().create_at(b"/f", 0o644).expect("create f");

    // The VFS type-agreement gate (`may_delete` → EISDIR) is what Linux uses
    // here; this backend-level call bypasses it, so the emptiness check is the
    // only thing standing between a file rename and a destroyed subtree.
    assert_eq!(m.state().rename_at(b"/f", b"/d"), Err(VfsError::Enotempty));
    assert!(m.state().mount.lookup_path(b"/d/child").is_ok(), "d/child survives");
}
