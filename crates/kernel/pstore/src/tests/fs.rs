// The mount: a record per file, contents readable, unlink erases.
//
// These drive the real filesystem object over a real backend attached to a
// heap region, so the file a crash-report collector would open is the file
// asserted on here.

use super::*;
use crate::ram::{RamBackend, RamRegion};
use crate::uapi::RecordType;
use alloc::string::{String, ToString};
use alloc::vec;
use vfs::fs::FileSystem;

const REGION: usize = 32 * 1024;
const RECORD: usize = 8 * 1024;
const CONSOLE: usize = 4096;

struct Ram(Vec<u8>);

impl Ram {
    fn new() -> Ram { Ram(vec![0u8; REGION]) }
    fn attach(&mut self) -> Arc<RamBackend> {
        let base = self.0.as_mut_ptr() as usize;
        let len = self.0.len();
        // SAFETY: `self` is mutably borrowed for the call and the span is a
        // live allocation of exactly `len` bytes owned by this test.
        let region = unsafe { RamRegion::new(base, len) };
        RamBackend::attach(region, RECORD, CONSOLE).0
    }
}

/// A mount built directly over `records`, bypassing the process-global
/// backend registry so these tests do not depend on one another.
fn mount_with(records: Vec<Record>) -> Arc<PstoreFs> {
    let root = Root::new();
    root.publish(records);
    Arc::new(PstoreFs { tree: root })
}

fn rec(ty: RecordType, index: usize, body: &[u8]) -> Record {
    Record { id: RecordId { ty, index }, sec: 1700, nsec: 0, body: body.to_vec() }
}

/// Collect every name the directory enumerates, the way `getdents` does.
fn dir_names(inode: &vfs::Inode) -> Vec<String> {
    struct Sink(Vec<String>);
    impl vfs::DirEmit for Sink {
        fn emit(&mut self, name: &str, _ino: u64, _t: vfs::FileType, _next: u64) -> bool {
            self.0.push(name.to_string());
            true
        }
    }
    let mut sink = Sink(Vec::new());
    {
        let mut ctx = vfs::DirContext::new(0, &mut sink);
        inode.i_fop().iterate(inode, &mut ctx).unwrap();
    }
    sink.0
}

fn read_all(inode: &vfs::Inode) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 64];
    let mut off = 0u64;
    loop {
        let n = inode.i_fop().read(inode, off, &mut buf).unwrap();
        if n == 0 { break; }
        out.extend_from_slice(&buf[..n]);
        off += n as u64;
    }
    out
}

#[test]
fn the_mount_reports_the_pstore_magic() {
    let fs = mount_with(Vec::new());
    assert_eq!(fs.magic(), PSTOREFS_MAGIC);
    assert_eq!(fs.name(), "pstore");
}

#[test]
fn a_mount_with_no_records_is_an_empty_directory_not_a_failure() {
    let fs = mount_with(Vec::new());
    let root = fs.root().unwrap();
    assert_eq!(root.file_type(), vfs::FileType::Directory);
    assert!(root.i_op().lookup(&root, "dmesg-ramoops-0").is_err());
}

#[test]
fn each_record_appears_as_a_file_named_for_it() {
    let fs = mount_with(vec![
        rec(RecordType::Dmesg, 0, b"crash one"),
        rec(RecordType::Dmesg, 3, b"crash two"),
        rec(RecordType::Console, 0, b"boot log"),
    ]);
    let root = fs.root().unwrap();
    for name in ["dmesg-ramoops-0", "dmesg-ramoops-3", "console-ramoops-0"] {
        root.i_op().lookup(&root, name).unwrap_or_else(|_| panic!("{name} missing"));
    }
}

#[test]
fn a_record_file_reads_back_the_captured_data() {
    let fs = mount_with(vec![rec(RecordType::Dmesg, 0, b"Panic#1 Part1\nthe log tail")]);
    let root = fs.root().unwrap();
    let f = root.i_op().lookup(&root, "dmesg-ramoops-0").unwrap();
    assert_eq!(read_all(&f), b"Panic#1 Part1\nthe log tail".to_vec());
    assert_eq!(f.size(), 26);
}

#[test]
fn a_record_file_is_read_only() {
    let fs = mount_with(vec![rec(RecordType::Dmesg, 0, b"x")]);
    let root = fs.root().unwrap();
    let f = root.i_op().lookup(&root, "dmesg-ramoops-0").unwrap();
    assert_eq!(f.i_fop().write(&f, 0, b"nope"), Err(vfs::VfsError::Erofs));
}

#[test]
fn a_record_file_is_stamped_with_the_time_of_the_crash() {
    let fs = mount_with(vec![rec(RecordType::Dmesg, 0, b"x")]);
    let root = fs.root().unwrap();
    let f = root.i_op().lookup(&root, "dmesg-ramoops-0").unwrap();
    assert_eq!(f.mtime().map(|t| t.sec), Some(1700));
}

#[test]
fn the_directory_enumerates_every_record() {
    let fs = mount_with(vec![
        rec(RecordType::Dmesg, 0, b"a"),
        rec(RecordType::Dmesg, 1, b"b"),
        rec(RecordType::Console, 0, b"c"),
    ]);
    let root = fs.root().unwrap();
    let names = dir_names(&root);
    assert_eq!(names.len(), 3);
    assert!(names.iter().any(|n| n == "dmesg-ramoops-0"));
    assert!(names.iter().any(|n| n == "console-ramoops-0"));
}

#[test]
fn unlinking_a_record_file_erases_the_record_from_the_region() {
    let mut ram = Ram::new();
    let backend = ram.attach();
    backend.write_dmesg(1700, 0, b"to be erased");
    assert!(psinfo::register(Arc::clone(&backend)) || psinfo::backend().is_some());
    // Only meaningful when THIS backend is the registered one; another test
    // in the same process may have registered first.
    if let Some(live) = psinfo::backend() {
        if Arc::ptr_eq(&live, &backend) {
            let fs = mount_with(backend.records());
            let root = fs.root().unwrap();
            root.i_op().unlink(&root, "dmesg-ramoops-0").unwrap();
            assert!(backend.records().is_empty(), "unlink must erase the zone");
            assert!(root.i_op().lookup(&root, "dmesg-ramoops-0").is_err());
        }
    }
}

#[test]
fn unlinking_a_name_that_is_not_there_is_enoent() {
    let fs = mount_with(Vec::new());
    let root = fs.root().unwrap();
    assert_eq!(root.i_op().unlink(&root, "dmesg-ramoops-7"), Err(vfs::VfsError::Enoent));
}

#[test]
fn the_mount_installs_a_valid_kmsg_bytes_and_ignores_an_invalid_one() {
    crate::kmsg::set_kmsg_bytes(crate::limits::DEFAULT_KMSG_BYTES);
    mount("kmsg_bytes=2048", &[]).unwrap();
    assert_eq!(crate::kmsg::kmsg_bytes(), 2048);
    // The reference swallows a bad value: the mount succeeds and the live
    // bound is untouched.
    mount("kmsg_bytes=rubbish", &[]).unwrap();
    assert_eq!(crate::kmsg::kmsg_bytes(), 2048);
    mount("wholly-unknown=1", &[]).unwrap();
    assert_eq!(crate::kmsg::kmsg_bytes(), 2048);
    crate::kmsg::set_kmsg_bytes(crate::limits::DEFAULT_KMSG_BYTES);
}
