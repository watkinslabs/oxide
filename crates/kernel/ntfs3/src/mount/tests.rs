use super::*;

use alloc::vec::Vec;
use block::{BlockDevice, BlockError, BlockOp, BlockRequest};
use vfs::CreateCtx;

const BLOCK_SIZE: u32 = 512;

struct Disk {
    bytes: sync::Spinlock<Vec<u8>, sync::TaskList>,
}

impl BlockDevice for Disk {
    fn block_size(&self) -> u32 { BLOCK_SIZE }

    fn capacity_blocks(&self) -> u64 {
        self.bytes.lock().len() as u64 / u64::from(BLOCK_SIZE)
    }

    fn submit_sync(&self, req: &mut BlockRequest) -> block::KResult<()> {
        let at = req.start_block as usize * BLOCK_SIZE as usize;
        let len = req.len_blocks as usize * BLOCK_SIZE as usize;
        let mut bytes = self.bytes.lock();
        if at.checked_add(len).is_none_or(|end| end > bytes.len()) {
            return Err(BlockError::Eio);
        }
        match req.op {
            BlockOp::Read => {
                req.buffer = bytes[at..at + len].to_vec();
                Ok(())
            }
            BlockOp::Write => {
                if req.buffer.len() < len { return Err(BlockError::Eio); }
                bytes[at..at + len].copy_from_slice(&req.buffer[..len]);
                Ok(())
            }
            BlockOp::Flush => Ok(()),
            _ => Err(BlockError::Eopnotsupp),
        }
    }

    fn flush(&self) -> block::KResult<()> { Ok(()) }
}

fn disk() -> Arc<Disk> {
    let mut b = crate::test_image::Builder::new();
    b.push_file("original.txt", b"one name, one record");
    b.push_dir("directory");
    Arc::new(Disk { bytes: sync::Spinlock::new(b.finish().snapshot()) })
}

fn mounted(disk: &Arc<Disk>) -> Arc<NtfsFs> {
    mounted_with(disk, Options::defaults())
}

fn mounted_with(disk: &Arc<Disk>, mut opts: Options) -> Arc<NtfsFs> {
    opts.settle();
    NtfsFs::open_with(Arc::clone(disk) as Arc<dyn BlockDevice>, "/dev/loop0", true, opts)
        .expect("mount")
}

fn stream_disk() -> Arc<Disk> {
    let mut b = crate::test_image::Builder::new();
    b.push_file_with_stream("report.txt", b"body", "secret", b"hidden");
    Arc::new(Disk { bytes: sync::Spinlock::new(b.finish().snapshot()) })
}

#[test]
fn alternate_streams_are_real_user_xattrs() {
    let fs = mounted_with(&stream_disk(), Options::defaults());
    let file = fs.root_inode().unwrap().lookup("report.txt").unwrap();
    assert_eq!(file.listxattr().unwrap(), alloc::vec!["user.secret"]);
    assert_eq!(file.getxattr("user.secret").unwrap(), b"hidden");
    assert_eq!(file.getxattr("user.missing"), Err(vfs::XattrError::NotFound));
    assert_eq!(file.setxattr("user.secret", b"new".to_vec(), false, true),
               Err(vfs::XattrError::NotSup));
}

#[test]
fn windows_streams_are_files_named_after_their_base_file() {
    let mut opts = Options::defaults();
    opts.streams = crate::opts::StreamInterface::Windows;
    let fs = mounted_with(&stream_disk(), opts);
    let file = fs.root_inode().unwrap().lookup("report.txt:secret").unwrap();
    let mut data = [0u8; 6];
    assert_eq!(file.read(0, &mut data).unwrap(), 6);
    assert_eq!(&data, b"hidden");
}

#[test]
fn hard_link_reaches_the_medium_through_the_vfs_operations() {
    let disk = disk();
    let fs = mounted(&disk);
    let root = fs.root_inode().expect("root");
    let original = root.lookup("original.txt").expect("original");

    root.link_child(&original, "second.txt", &CreateCtx::root()).expect("hard link");
    let second = root.lookup("second.txt").expect("second name");
    assert_eq!(second.ino(), original.ino(), "both names resolve to one record");
    assert_eq!(original.nlink(), 2, "the cached target count follows the medium");
    assert_eq!(second.nlink(), 2, "a fresh lookup reads the record count");
    let mut data = [0u8; 32];
    let got = second.read(0, &mut data).expect("read through second name");
    assert_eq!(&data[..got], b"one name, one record");

    root.unlink_child("original.txt").expect("remove first name");
    assert!(root.lookup("original.txt").is_err());
    let second = root.lookup("second.txt").expect("second survives");
    assert_eq!(second.nlink(), 1);
    let node = second.private::<super::node::NtfsNode>().expect("NTFS node");
    let (record, attrs) = fs.volume.lock().read_record(node.info.number).expect("record");
    let names = attrs.iter().filter(|attr| attr.ty == crate::uapi::ATTR_NAME)
        .filter(|attr| attr.resident_span().is_some_and(|(start, end)| {
            crate::name::parse_filename(&record[start..end]).is_some()
        })).count();
    assert_eq!(names, 1, "unlink removes the matching name attribute");

    fs.mark_clean().expect("clean unmount state");
    drop(fs);
    let remounted = mounted(&disk);
    let root = remounted.root_inode().expect("remounted root");
    let second = root.lookup("second.txt").expect("second persisted");
    assert_eq!(second.nlink(), 1);
    let mut data = [0u8; 32];
    let got = second.read(0, &mut data).expect("remounted data");
    assert_eq!(&data[..got], b"one name, one record");
}

#[test]
fn hard_link_refuses_a_directory_and_an_existing_name() {
    let disk = disk();
    let fs = mounted(&disk);
    let root = fs.root_inode().expect("root");
    let original = root.lookup("original.txt").expect("original");
    let directory = root.lookup("directory").expect("directory");

    assert_eq!(root.link_child(&directory, "dir-link", &CreateCtx::root()), Err(VfsError::Eperm));
    assert_eq!(root.link_child(&original, "directory", &CreateCtx::root()), Err(VfsError::Eexist));
}

#[test]
fn a_grown_directory_keeps_a_link_reachable_on_the_target() {
    let disk = disk();
    let fs = mounted(&disk);
    let root = fs.root_inode().expect("root");
    let original = root.lookup("original.txt").expect("original");
    for i in 0..100 {
        let name = alloc::format!("fill-{i}");
        if root.create_child(&name, 0o644, &CreateCtx::root()).is_err() { break; }
    }
    root.link_child(&original, "cannot-fit", &CreateCtx::root()).expect("allocation-backed link");
    assert_eq!(original.nlink(), 2);
    assert!(root.lookup("cannot-fit").is_ok());

    let node = original.private::<super::node::NtfsNode>().expect("NTFS node");
    let (record, attrs) = fs.volume.lock().read_record(node.info.number).expect("record");
    let names = attrs.iter().filter(|attr| attr.ty == crate::uapi::ATTR_NAME)
        .filter(|attr| attr.resident_span().is_some_and(|(start, end)| {
            crate::name::parse_filename(&record[start..end]).is_some()
        })).count();
    assert_eq!(names, 2, "the new hard link adds one target name");
}
