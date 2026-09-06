//! Canonical VFS mkdir publishes parent links and directory geometry durably.
extern crate alloc;
mod common;

use std::sync::Arc;
use block::{BlockDevice, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::{Dentry, File, OpenFlags};
use vfs::fs::FileSystem;

const SECTOR: u32 = 512;
const PLAIN: &[u8] = include_bytes!("mini.img");
const JOURNAL: &[u8] = include_bytes!("mini-j.img");

fn disk(image: &[u8]) -> Arc<MemDisk<TaskList>> {
    let dev = MemDisk::new(SECTOR, image.len() as u64 / SECTOR as u64);
    let mut write = BlockRequest::new_write(0, (image.len() / SECTOR as usize) as u32, image.to_vec());
    dev.submit_sync(&mut write).unwrap();
    dev
}

fn mount(image: &[u8]) -> (Arc<MemDisk<TaskList>>, Arc<ext4::rootfs::Ext4Mount>, Arc<vfs::SuperBlock>) {
    common::boot_hosted_pmm();
    let dev = disk(image);
    let fs = ext4::rootfs::Ext4Mount::open(dev.clone()).unwrap();
    let sb = common::realize_sb(fs.clone(), fs.root(), 0, "ext4".into());
    (dev, fs, sb)
}

fn snapshot(dev: &dyn BlockDevice) -> Arc<MemDisk<TaskList>> {
    let mut read = BlockRequest::new_read(0, dev.capacity_blocks() as u32, SECTOR);
    dev.submit_sync(&mut read).unwrap();
    disk(&read.buffer)
}

fn parent(fs: &ext4::rootfs::Ext4Mount) -> vfs::InodeRef {
    let root = fs.root().unwrap();
    let _guard = root.inode_lock();
    // Instantiate after set_sb: the bootstrap root wrapper predates canonical
    // inode-cache ownership and would exercise the raw helper path instead.
    let parent = root.mkdir("parent", 0o755, &vfs::CreateCtx::root()).unwrap();
    assert!(Arc::ptr_eq(&parent, &root.lookup("parent").unwrap()));
    parent
}

fn parent_links_survive(image: &[u8]) {
    let (dev, fs, _sb) = mount(image);
    let root = parent(&fs);
    let links = root.nlink();
    fs.state().mount.begin_batch();
    for name in ["first", "second", "third"] {
        let _guard = root.inode_lock();
        root.mkdir(name, 0o755, &vfs::CreateCtx::root()).unwrap();
    }
    assert_eq!(root.nlink(), links + 3);
    let file = File::new(root.clone(), Dentry::new_root(root), OpenFlags::O_RDONLY);
    file.vfs_fsync(false).unwrap();
    // Snapshot before dropping the original mount: Drop must not hide a missing commit.
    let recovered = ext4::Mount::open(snapshot(&*dev)).unwrap();
    let parent_ino = recovered.lookup_path(b"/parent").unwrap();
    let disk_links = recovered.read_inode(parent_ino).unwrap().links_count;
    for name in [b"/parent/first".as_slice(), b"/parent/second", b"/parent/third"] {
        let ino = recovered.lookup_path(name).unwrap();
        assert_eq!(recovered.read_inode(ino).unwrap().links_count, 2);
    }
    assert_eq!(disk_links as u32, links + 3, "VFS mkdir lost persisted parent links");
}

#[test]
fn canonical_mkdir_parent_links_survive_journal_replay() { parent_links_survive(JOURNAL); }

#[test]
fn canonical_mkdir_parent_links_survive_nojournal_fsync() { parent_links_survive(PLAIN); }

#[test]
fn canonical_mkdir_parent_write_failure_rolls_back_and_retries() {
    let (dev, fs, _sb) = mount(JOURNAL);
    let parent = parent(&fs);
    let parent_ino = fs.state().mount.lookup_path(b"/parent").unwrap();
    let links = parent.nlink();
    fs.state().mount.begin_batch();
    fs.state().mount.fail_inode_write_for_tests(parent_ino, 0);
    {
        let _guard = parent.inode_lock();
        assert!(parent.mkdir("failed", 0o755, &vfs::CreateCtx::root()).is_err());
    }
    assert_eq!(parent.nlink(), links);
    assert!(parent.lookup("failed").is_err());
    let file = File::new(parent.clone(), Dentry::new_root(parent.clone()), OpenFlags::O_RDONLY);
    file.vfs_fsync(false).unwrap();
    let recovered = ext4::Mount::open(snapshot(&*dev)).unwrap();
    assert!(recovered.lookup_path(b"/parent/failed").is_err());
    assert_eq!(recovered.read_inode(parent_ino).unwrap().links_count as u32, links);
    {
        let _guard = parent.inode_lock();
        parent.mkdir("retry", 0o755, &vfs::CreateCtx::root()).unwrap();
    }
    file.vfs_fsync(false).unwrap();
    let recovered = ext4::Mount::open(snapshot(&*dev)).unwrap();
    recovered.lookup_path(b"/parent/retry").unwrap();
    assert_eq!(recovered.read_inode(parent_ino).unwrap().links_count as u32, links + 1);
}

#[test]
fn canonical_mkdir_publishes_growth_before_return_and_reuses_mapping() {
    let (_dev, fs, _sb) = mount(PLAIN);
    let root = parent(&fs);
    let parent_ino = fs.state().mount.lookup_path(b"/parent").unwrap();
    fs.state().mount.begin_batch();
    let initial = root.size();
    let mut names = Vec::new();
    let mut grew = false;
    for i in 0..40 {
        let name = format!("child-{i:03}-{}", "x".repeat(180));
        let _guard = root.inode_lock();
        let child = root.mkdir(&name, 0o755, &vfs::CreateCtx::root()).unwrap();
        let raw = fs.state().mount.read_inode(parent_ino).unwrap();
        assert_eq!(root.size(), raw.size, "mkdir returned stale parent i_size");
        assert_eq!(root.getattr(&vfs::Idmap::identity()).blocks, raw.i_blocks,
            "mkdir returned stale parent i_blocks");
        names.push((name, child));
        if raw.size > initial { grew = true; break; }
    }
    assert!(grew, "fixture must exercise directory growth");
    // A resident child needs no inode read. Neither should a canonical parent
    // whose new mapping was published by its namespace mutation owner.
    fs.state().mount.reset_inode_read_count_for_tests();
    for (name, child) in &names {
        let got = root.lookup(name).unwrap();
        assert!(Arc::ptr_eq(&got, child));
    }
    assert_eq!(fs.state().mount.inode_read_count_for_tests(), 0,
        "post-mkdir lookup used invalidated/stale canonical geometry");
}
