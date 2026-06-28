//! `init_special_inode` (Linux fs/inode.c) — bind the op set by S_IFMT.
//! S_IFCHR/S_IFBLK get a device node (rdev set, def_chr/blk dispatch),
//! S_IFIFO a fifo, S_IFSOCK a socket inode; rdev is ignored for fifo/sock,
//! a socket node cannot be opened by path (ENXIO, Linux `sock_no_open`), and
//! a fifo/socket node is not directly readable as a file (the pipe/socket
//! f_op is bound by the pipe/socket subsystem at open, not the bare inode).

use std::sync::Arc;

use vfs::devnode::{init_special_inode, FifoInode, SocketInode};
use vfs::inode::Inode;
use vfs::superblock::{FileSystemType, SbStatFs, SuperBlock, SuperOps};
use vfs::{CharDevOps, Devt, FileType, KResult, VfsError};

struct NullType;
impl FileSystemType for NullType {
    fn name(&self) -> &str { "t" }
    fn mount(&self, _s: &str, _o: &str) -> KResult<Arc<SuperBlock>> { unreachable!() }
}
struct NullOps;
impl SuperOps for NullOps {
    fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs::default()) }
}
fn sb(dev: u64) -> Arc<SuperBlock> {
    SuperBlock::new(Arc::new(NullType), Arc::new(NullOps), 0, dev, 4096, "t".into(), Arc::new(()))
}

// mem char driver: (1,5)=zero returns zeros.
struct MemChar;
impl CharDevOps for MemChar {
    fn read(&self, devt: Devt, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        match devt.minor() { 5 => { buf.fill(0); Ok(buf.len()) } _ => Err(VfsError::Enxio) }
    }
}

#[test]
fn chr_node_carries_rdev_and_routes_to_device() {
    vfs::register_chrdev(1, Arc::new(MemChar));
    let s = sb(0x10);
    let rdev = Devt::new(1, 5).raw();
    let n = init_special_inode(100, FileType::CharDev, rdev, 0o666, Arc::downgrade(&s)).unwrap();
    assert_eq!(n.file_type(), FileType::CharDev);
    assert_eq!(n.rdev(), rdev, "S_IFCHR keeps the rdev passed in");
    let mut buf = [0xffu8; 8];
    assert_eq!(n.read(0, &mut buf).unwrap(), 8, "read routes to the registered char driver");
    assert_eq!(buf, [0u8; 8]);
    vfs::unregister_chrdev(1);
}

#[test]
fn blk_node_carries_rdev() {
    let s = sb(0x11);
    let rdev = Devt::new(8, 0).raw();
    let n = init_special_inode(7, FileType::BlockDev, rdev, 0o660, Arc::downgrade(&s)).unwrap();
    assert_eq!(n.file_type(), FileType::BlockDev);
    assert_eq!(n.rdev(), rdev, "S_IFBLK keeps the rdev passed in");
    // No driver registered for major 8 here → device dispatch misses with ENXIO.
    let mut buf = [0u8; 4];
    assert_eq!(n.read(0, &mut buf), Err(VfsError::Enxio));
}

#[test]
fn fifo_node_typed_ignores_rdev_and_not_readable() {
    let s = sb(0x12);
    // Linux ignores rdev for S_IFIFO — pass a bogus number, expect rdev()==0.
    let n = init_special_inode(200, FileType::Fifo, Devt::new(9, 9).raw(), 0o644, Arc::downgrade(&s)).unwrap();
    assert_eq!(n.file_type(), FileType::Fifo);
    assert_eq!(n.rdev(), 0, "a FIFO has no device number");
    assert_eq!(n.perm(), Some(0o644));
    // The bare inode has no data op (pipe f_op binds at open) → not readable.
    let mut buf = [0u8; 4];
    assert_eq!(n.read(0, &mut buf), Err(VfsError::Einval));
    assert_eq!(n.write(0, b"x"), Err(VfsError::Einval));
}

#[test]
fn socket_node_typed_ignores_rdev_open_enxio() {
    let s = sb(0x13);
    let n = init_special_inode(201, FileType::Socket, Devt::new(9, 9).raw(), 0o666, Arc::downgrade(&s)).unwrap();
    assert_eq!(n.file_type(), FileType::Socket);
    assert_eq!(n.rdev(), 0, "a socket node has no device number");
    let mut buf = [0u8; 4];
    assert_eq!(n.read(0, &mut buf), Err(VfsError::Einval), "socket node not directly readable");
    // sock_no_open: opening a socket node by path returns ENXIO.
    let direct = SocketInode::new(201, 0o666, Arc::downgrade(&s));
    assert_eq!(direct.do_open(), Err(VfsError::Enxio));
}

#[test]
fn fifo_direct_constructor_matches() {
    let s = sb(0x14);
    let f = FifoInode::new(300, 0o600, Arc::downgrade(&s));
    assert_eq!(f.file_type(), FileType::Fifo);
    assert_eq!(f.rdev(), 0);
    assert_eq!(f.ino(), 300);
}

#[test]
fn bogus_type_rejected() {
    let s = sb(0x15);
    // init_special_inode is only for char/block/fifo/sock (Linux logs "bogus
    // i_mode" for anything else); a regular/dir/symlink type is rejected.
    for ft in [FileType::Regular, FileType::Directory, FileType::Symlink] {
        assert_eq!(init_special_inode(1, ft, 0, 0o644, Arc::downgrade(&s)).err(), Some(VfsError::Einval));
    }
}
