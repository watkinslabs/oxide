//! `getdents(2)`/`getdents64(2)` over a REAL tmpfs directory, through the same
//! `vfs::readdir_dots` driver the syscall shim uses.
//!
//! Linux reserves readdir cursors 0 and 1 for `.` and `..` (`dir_emit_dots`,
//! `include/linux/fs.h`) and every filesystem emits them. tmpfs (and every other
//! synthetic backend here) stores only real children, so the VFS synthesises the
//! dots and shifts the backend's cookie space past them. Without that, `ls -a`
//! on /run, /tmp, /dev, /proc and /sys shows no `.`/`..`, `find` cannot walk
//! upward, and any `..`-comparing `getcwd(3)` fallback fails.
//!
//! The packed-record side (both `linux_dirent` layouts, the too-small-buffer
//! EINVAL, the return rule) is pinned by `syscalls::getdents_abi`'s own tests.

use std::string::String;
use std::sync::Arc;
use std::vec::Vec;

use fs::tmpfs::TmpfsFs;
use vfs::inode_ops::CreateCtx;
use vfs::{DType, DirEmit, FileType};

/// Every record the driver offered, in order.
#[derive(Debug, PartialEq, Eq)]
struct Rec { name: String, ino: u64, dt: u8, next: u64 }

/// Actor that records what it is offered and optionally refuses after `cap`
/// records, modelling a full user buffer.
struct Sink { recs: Vec<Rec>, cap: usize }

impl Sink {
    fn new() -> Self { Sink { recs: Vec::new(), cap: usize::MAX } }
    fn capped(cap: usize) -> Self { Sink { recs: Vec::new(), cap } }
    fn names(&self) -> Vec<&str> { self.recs.iter().map(|r| r.name.as_str()).collect() }
}

impl DirEmit for Sink {
    fn emit(&mut self, name: &str, ino: u64, d_type: FileType, next_pos: u64) -> bool {
        self.emit_dt(name, ino, DType::from_file_type(d_type), next_pos)
    }
    fn emit_dt(&mut self, name: &str, ino: u64, d_type: DType, next_pos: u64) -> bool {
        if self.recs.len() >= self.cap { return false; }
        self.recs.push(Rec { name: name.into(), ino, dt: d_type.raw(), next: next_pos });
        true
    }
}

/// `/fixture` with one child of each type the dirent ABI can name.
fn fixture() -> (Arc<TmpfsFs>, vfs::InodeRef, vfs::InodeRef) {
    let fs = TmpfsFs::new(String::from("fixture"));
    let root = fs.root_inode();
    let dir = root.mkdir("dir", 0o755, &CreateCtx::root()).expect("mkdir dir");
    dir.mkdir("sub", 0o755, &CreateCtx::root()).expect("mkdir sub");
    dir.create_child("file", 0o644, &CreateCtx::root()).expect("create file");
    dir.symlink_child("link", b"file", &CreateCtx::root()).expect("symlink");
    dir.mknod_child("fifo", (vfs::S_IFIFO as u16) | 0o644, 0, &CreateCtx::root()).expect("mknod fifo");
    dir.mknod_child("sock", (vfs::S_IFSOCK as u16) | 0o644, 0, &CreateCtx::root()).expect("mknod sock");
    dir.mknod_child("chr", (vfs::S_IFCHR as u16) | 0o600, vfs::mkdev(1, 3), &CreateCtx::root()).expect("mknod chr");
    dir.mknod_child("blk", (vfs::S_IFBLK as u16) | 0o600, vfs::mkdev(8, 0), &CreateCtx::root()).expect("mknod blk");
    (fs, root, dir)
}

/// tmpfs stores only real children, so the VFS must supply `.` and `..` — at
/// cursors 0 and 1, in that order, before any child, with the right inode
/// numbers.
#[test]
fn tmpfs_directory_leads_with_dot_and_dotdot() {
    let (_fs, root, dir) = fixture();
    assert!(!dir.dir_emits_dots(), "tmpfs has no on-disk dots of its own");

    let mut sink = Sink::new();
    let (r, end) = vfs::readdir_dots(&dir, dir.ino(), root.ino(), 0, &mut sink);
    r.expect("readdir");

    assert_eq!(sink.recs[0].name, ".");
    assert_eq!(sink.recs[0].ino, dir.ino(), "'.' is this directory");
    assert_eq!(sink.recs[0].dt, vfs::dirent::DT_DIR);
    assert_eq!(sink.recs[0].next, 1, "'.' occupies cursor 0, '..' resumes at 1");

    assert_eq!(sink.recs[1].name, "..");
    assert_eq!(sink.recs[1].ino, root.ino(), "'..' is the parent");
    assert_eq!(sink.recs[1].dt, vfs::dirent::DT_DIR);
    assert_eq!(sink.recs[1].next, 2, "children begin at cursor 2");

    let names = sink.names();
    assert_eq!(&names[..2], &[".", ".."]);
    assert_eq!(names.len(), 2 + 7, "both dots plus every real child");
    assert!(end >= 2);
}

/// A filesystem root's `..` resolves back to the root itself (Linux
/// `d_parent_ino` of a root dentry is the dentry itself).
#[test]
fn root_dotdot_is_the_root_itself() {
    let (_fs, root, _dir) = fixture();
    let mut sink = Sink::new();
    let (r, _) = vfs::readdir_dots(&root, root.ino(), root.ino(), 0, &mut sink);
    r.expect("readdir");
    assert_eq!(sink.recs[1].name, "..");
    assert_eq!(sink.recs[1].ino, root.ino());
}

/// tmpfs knows every child's real type, so `d_type` is never `DT_UNKNOWN` and
/// never a blanket `DT_REG`: `ls -F` / `find -type` work without a per-entry
/// `stat`.
#[test]
fn tmpfs_reports_a_real_d_type_per_entry() {
    use vfs::dirent::{DT_BLK, DT_CHR, DT_DIR, DT_FIFO, DT_LNK, DT_REG, DT_SOCK, DT_UNKNOWN};
    let (_fs, root, dir) = fixture();
    let mut sink = Sink::new();
    let (r, _) = vfs::readdir_dots(&dir, dir.ino(), root.ino(), 0, &mut sink);
    r.expect("readdir");
    let want = [(".", DT_DIR), ("..", DT_DIR), ("blk", DT_BLK), ("chr", DT_CHR),
                ("fifo", DT_FIFO), ("file", DT_REG), ("link", DT_LNK), ("sock", DT_SOCK),
                ("sub", DT_DIR)];
    for (name, dt) in want {
        let rec = sink.recs.iter().find(|r| r.name == name).expect(name);
        assert_eq!(rec.dt, dt, "{name} d_type");
        assert_ne!(rec.dt, DT_UNKNOWN, "{name}: tmpfs always knows the type");
    }
    assert_eq!(sink.recs.len(), want.len());
}

/// Child cookies are shifted past the two reserved dot cursors, and a resume
/// from any cookie yields exactly the suffix — no replay, no skip. This is the
/// `telldir`/`seekdir` and paginated-`getdents` contract.
#[test]
fn resuming_from_a_d_off_cookie_yields_the_exact_suffix() {
    let (_fs, root, dir) = fixture();
    let mut all = Sink::new();
    let (r, end) = vfs::readdir_dots(&dir, dir.ino(), root.ino(), 0, &mut all);
    r.expect("readdir");
    let full: Vec<String> = all.recs.iter().map(|r| r.name.clone()).collect();
    // Cookies are strictly increasing positions, starting at 1 for '.'.
    let cookies: Vec<u64> = all.recs.iter().map(|r| r.next).collect();
    assert!(cookies.windows(2).all(|w| w[0] < w[1]), "cookies strictly increase: {cookies:?}");
    assert_eq!(cookies[0], 1);
    assert_eq!(cookies[1], 2, "the first child sits at cursor 2, past both dots");
    assert_eq!(end, *cookies.last().unwrap());

    for split in 0..full.len() {
        let resume = all.recs[split].next;
        let mut rest = Sink::new();
        let (r2, _) = vfs::readdir_dots(&dir, dir.ino(), root.ino(), resume, &mut rest);
        r2.expect("readdir resume");
        let got: Vec<String> = rest.recs.iter().map(|r| r.name.clone()).collect();
        assert_eq!(got, full[split + 1..], "resume from cookie {resume}");
    }
}

/// A buffer that fills mid-dots stops there and does not advance into children:
/// the unemitted dot is retried on the next call rather than lost.
#[test]
fn a_full_buffer_inside_the_dots_retries_them() {
    let (_fs, root, dir) = fixture();
    for cap in [0usize, 1] {
        let mut sink = Sink::capped(cap);
        let (r, end) = vfs::readdir_dots(&dir, dir.ino(), root.ino(), 0, &mut sink);
        r.expect("readdir");
        assert_eq!(sink.recs.len(), cap);
        assert_eq!(end, cap as u64, "cursor stops exactly at the unemitted dot");
    }
}

/// Paginating a whole directory two records at a time reconstructs it exactly
/// once, dots included.
#[test]
fn paginated_read_reconstructs_the_directory_exactly_once() {
    let (_fs, root, dir) = fixture();
    let mut seen: Vec<String> = Vec::new();
    let mut pos = 0u64;
    loop {
        let mut page = Sink::capped(2);
        let (r, end) = vfs::readdir_dots(&dir, dir.ino(), root.ino(), pos, &mut page);
        r.expect("readdir page");
        if page.recs.is_empty() { break; }
        for rec in &page.recs { seen.push(rec.name.clone()); }
        assert!(end > pos, "a page that emitted records must advance the cursor");
        pos = end;
    }
    let mut sorted = seen.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), seen.len(), "no entry seen twice: {seen:?}");
    assert_eq!(seen.len(), 9, ". + .. + 7 children");
    assert!(seen.contains(&String::from(".")) && seen.contains(&String::from("..")));
}
