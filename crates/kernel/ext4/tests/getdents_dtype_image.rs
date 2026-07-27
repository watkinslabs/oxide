//! `getdents`/`getdents64` `d_type` honesty and cursor behaviour over a REAL
//! ext4 image, through the same `vfs::readdir_dots` driver the syscall shim
//! uses.
//!
//! ext4 stores a `d_type` byte per on-disk directory record, but ONLY when
//! `EXT4_FEATURE_INCOMPAT_FILETYPE` is set; without it byte 7 of a record is the
//! high half of `name_len` (always 0 for a name <= 255). Reading it regardless
//! reports `DT_UNKNOWN`-as-`DT_REG` for EVERY entry, subdirectories included, so
//! `find -type d`, `ls -F` and `fts` walk the wrong tree. The honest answer for
//! an image without the feature is `DT_UNKNOWN`, which `readdir(3)` resolves
//! with a `stat`.
//!
//! ext4 also carries `.` and `..` as real on-disk records, so it must opt OUT of
//! the VFS dot synthesis or every listing would show them twice.

extern crate alloc;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::dirent::{DT_DIR, DT_LNK, DT_REG, DT_UNKNOWN};
use vfs::{DType, DirEmit, FileType};

const IMAGE: &[u8] = include_bytes!("mini.img");
const SECTOR: u32 = 512;

fn build_disk() -> Arc<dyn BlockDevice> {
    let cap = (IMAGE.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest {
        op: BlockOp::Write, start_block: 0, len_blocks: cap as u32, buffer: IMAGE.to_vec(),
    };
    disk.submit_sync(&mut req).unwrap();
    disk
}

#[derive(Debug)]
struct Rec { name: String, ino: u64, dt: u8, next: u64 }

struct Sink { recs: Vec<Rec>, cap: usize }

impl Sink {
    fn new() -> Self { Sink { recs: Vec::new(), cap: usize::MAX } }
    fn capped(cap: usize) -> Self { Sink { recs: Vec::new(), cap } }
    fn find(&self, name: &str) -> Option<&Rec> { self.recs.iter().find(|r| r.name == name) }
    fn names(&self) -> Vec<String> { self.recs.iter().map(|r| r.name.clone()).collect() }
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

/// Populate `/dtypes` with one child per representable type and list it.
fn listing() -> (Arc<ext4::rootfs::Ext4Mount>, vfs::InodeRef, Sink) {
    let m = ext4::rootfs::Ext4Mount::open(build_disk()).unwrap();
    let st = m.state();
    let root = st.wrap_any_ino(2).expect("root inode");
    let dir = root.mkdir("dtypes", 0o755, &vfs::inode_ops::CreateCtx::root()).expect("mkdir");
    dir.mkdir("sub", 0o755, &vfs::inode_ops::CreateCtx::root()).expect("mkdir sub");
    dir.create_child("file", 0o644, &vfs::inode_ops::CreateCtx::root()).expect("create");
    dir.symlink_child("link", b"file", &vfs::inode_ops::CreateCtx::root()).expect("symlink");
    let mut sink = Sink::new();
    let (r, _end) = vfs::readdir_dots(&dir, dir.ino(), root.ino(), 0, &mut sink);
    r.expect("readdir");
    (m, dir, sink)
}

/// The on-disk `file_type` byte is decoded per entry: a directory reports
/// `DT_DIR`, a symlink `DT_LNK`, a regular file `DT_REG`. `mini.img` has
/// `EXT4_FEATURE_INCOMPAT_FILETYPE`, so nothing is `DT_UNKNOWN`.
#[test]
fn ext4_reports_the_on_disk_d_type_per_entry() {
    let (_m, _dir, sink) = listing();
    assert_eq!(sink.find("sub").expect("sub").dt, DT_DIR);
    assert_eq!(sink.find("file").expect("file").dt, DT_REG);
    assert_eq!(sink.find("link").expect("link").dt, DT_LNK);
    for r in &sink.recs {
        assert_ne!(r.dt, DT_UNKNOWN, "{}: this image has INCOMPAT_FILETYPE", r.name);
        assert_ne!(r.ino, 0, "{}: d_ino 0 reads as a deleted entry", r.name);
    }
}

/// ext4's own `.`/`..` records are used; the VFS must not prepend a second
/// pair.
#[test]
fn ext4_supplies_its_own_dots_exactly_once() {
    let (_m, dir, sink) = listing();
    assert!(dir.dir_emits_dots(), "ext4 carries dots on disk");
    let names = sink.names();
    assert_eq!(names.iter().filter(|n| *n == ".").count(), 1, "{names:?}");
    assert_eq!(names.iter().filter(|n| *n == "..").count(), 1, "{names:?}");
    assert_eq!(&names[0], ".", "'.' leads the listing");
    assert_eq!(&names[1], "..");
    assert_eq!(sink.find(".").unwrap().dt, DT_DIR);
    assert_eq!(sink.find("..").unwrap().dt, DT_DIR);
}

/// Every record's `d_off` is a resume cookie: seeking to it and re-reading
/// yields exactly the entries after it — no replay, no skip.
#[test]
fn d_off_cookies_resume_at_the_next_entry() {
    let (m, _dir, all) = listing();
    let st = m.state();
    let root = st.wrap_any_ino(2).expect("root");
    let dir = st.lookup_inode_any(b"/dtypes").expect("lookup /dtypes");
    let full = all.names();
    assert!(full.len() >= 5, "dots + three children: {full:?}");

    let cookies: Vec<u64> = all.recs.iter().map(|r| r.next).collect();
    assert!(cookies.windows(2).all(|w| w[0] < w[1]), "cookies increase: {cookies:?}");

    for split in 0..full.len() {
        let mut rest = Sink::new();
        let (r, _) = vfs::readdir_dots(&dir, dir.ino(), root.ino(), all.recs[split].next, &mut rest);
        r.expect("readdir resume");
        assert_eq!(rest.names(), full[split + 1..], "resume from {}", all.recs[split].next);
    }
}

/// Paginating with a buffer that holds two records at a time returns the whole
/// directory exactly once — the `getdents` loop `ls` actually runs.
#[test]
fn paginated_listing_is_complete_and_duplicate_free() {
    let (m, _d, all) = listing();
    let st = m.state();
    let root = st.wrap_any_ino(2).expect("root");
    let dir = st.lookup_inode_any(b"/dtypes").expect("lookup /dtypes");

    let mut seen: Vec<String> = Vec::new();
    let mut pos = 0u64;
    loop {
        let mut page = Sink::capped(2);
        let (r, end) = vfs::readdir_dots(&dir, dir.ino(), root.ino(), pos, &mut page);
        r.expect("readdir page");
        if page.recs.is_empty() { break; }
        seen.extend(page.names());
        assert!(end > pos, "a page that emitted records must advance the cursor");
        pos = end;
    }
    assert_eq!(seen, all.names(), "paginated read equals the single-shot read");
    let mut sorted = seen.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), seen.len(), "no entry twice: {seen:?}");
}

/// Without `EXT4_FEATURE_INCOMPAT_FILETYPE` byte 7 is not a type at all, so the
/// honest answer is `DT_UNKNOWN` for every entry rather than a fabricated
/// `DT_REG` that hides subdirectories from `find`.
#[test]
fn a_filetype_less_image_reports_dt_unknown_not_dt_reg() {
    use ext4::dir::dirent_dtype;
    // With the feature: the byte is decoded.
    assert_eq!(dirent_dtype(true, ext4::dir::DT_DIR).raw(), DT_DIR);
    assert_eq!(dirent_dtype(true, ext4::dir::DT_REG).raw(), DT_REG);
    assert_eq!(dirent_dtype(true, ext4::dir::DT_LNK).raw(), DT_LNK);
    // `EXT4_FT_UNKNOWN`, and any out-of-range byte, is DT_UNKNOWN.
    assert_eq!(dirent_dtype(true, 0).raw(), DT_UNKNOWN);
    assert_eq!(dirent_dtype(true, 200).raw(), DT_UNKNOWN);
    // Without the feature, EVERY byte is DT_UNKNOWN — including the values that
    // would otherwise decode to a directory.
    for b in 0u8..=8 {
        assert_eq!(dirent_dtype(false, b).raw(), DT_UNKNOWN,
                   "byte {b} is name_len's high half, not a type");
    }
}
