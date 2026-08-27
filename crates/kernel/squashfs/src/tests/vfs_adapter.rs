//! The VFS adapter over a mounted image: `SquashFs` on a real block device,
//! its root inode, and the inode/file operations a path walk reaches.
//!
//! Every other test in this crate stops at [`crate::volume::Volume`] — the
//! layer below the VFS — so the adapter that a mount, and a ROOT mount in
//! particular, actually runs had no coverage at all. What a root filesystem
//! must answer is exactly what is asserted here: a root inode exists, a name
//! resolves under it, a file's bytes come back through `FileOps::read`, a
//! symlink reports its target, and a write is refused the way an immutable
//! filesystem refuses one.

use alloc::sync::Arc;
use alloc::vec;

use vfs::{FileType, InodeRef, VfsError};

use crate::mount::SquashFs;
use crate::test_image::Builder;

/// The image every case below is built from, laid onto a real `MemDisk` and
/// mounted through the adapter rather than through `Volume`.
fn mount(bytes: alloc::vec::Vec<u8>) -> Arc<SquashFs> {
    const BS: u32 = 512;
    let blocks = bytes.len().div_ceil(BS as usize) as u64;
    let dev: Arc<dyn block::BlockDevice> =
        block::blockdev::MemDisk::<sync::TaskList>::new(BS, blocks);
    let mut padded = bytes;
    padded.resize((blocks as usize) * (BS as usize), 0);
    let mut req = block::BlockRequest::new_write(0, blocks as u32, padded);
    dev.submit_sync(&mut req).expect("stage the image onto the device");
    SquashFs::open(dev, "/dev/testdisk").expect("mount the staged image")
}

fn fixture() -> Arc<SquashFs> {
    mount(Builder::new()
        .file("hello", b"hello, squashfs")
        .symlink("link", "hello")
        .build_bytes())
}

fn lookup(root: &InodeRef, name: &str) -> Result<InodeRef, VfsError> {
    root.i_op().lookup(root, name)
}

#[test]
fn a_mounted_image_has_a_root_directory_inode() {
    let fs = fixture();
    let root = fs.root_inode().expect("root inode");
    assert_eq!(root.file_type(), FileType::Directory);
}

#[test]
fn a_stored_name_resolves_under_the_root() {
    let fs = fixture();
    let root = fs.root_inode().unwrap();
    let child = lookup(&root, "hello").expect("hello resolves");
    assert_eq!(child.file_type(), FileType::Regular);
    assert_eq!(child.size(), b"hello, squashfs".len() as u64);
}

#[test]
fn a_name_that_is_not_stored_is_enoent() {
    let fs = fixture();
    let root = fs.root_inode().unwrap();
    assert_eq!(lookup(&root, "absent").err(), Some(VfsError::Enoent));
}

#[test]
fn a_files_bytes_come_back_through_the_file_operations() {
    let fs = fixture();
    let root = fs.root_inode().unwrap();
    let child = lookup(&root, "hello").unwrap();
    let mut buf = vec![0u8; 32];
    let n = child.i_fop().read(&child, 0, &mut buf).expect("read");
    assert_eq!(&buf[..n], b"hello, squashfs");
}

#[test]
fn a_read_at_an_offset_starts_there() {
    let fs = fixture();
    let root = fs.root_inode().unwrap();
    let child = lookup(&root, "hello").unwrap();
    let mut buf = vec![0u8; 8];
    let n = child.i_fop().read(&child, 7, &mut buf).expect("read");
    assert_eq!(&buf[..n], b"squashfs");
}

#[test]
fn a_symlink_reports_the_target_it_stores() {
    let fs = fixture();
    let root = fs.root_inode().unwrap();
    let link = lookup(&root, "link").expect("link resolves");
    assert_eq!(link.file_type(), FileType::Symlink);
    assert_eq!(link.i_op().readlink(&link).expect("readlink"), b"hello".to_vec());
}

#[test]
fn the_mount_reports_the_device_it_was_opened_from() {
    assert_eq!(fixture().source(), "/dev/testdisk");
}

#[test]
fn the_format_is_never_writable() {
    assert!(!fixture().is_writable());
}
