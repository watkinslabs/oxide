//! file-D31: the buffered read path advances the per-open `f_ra` readahead
//! window (Linux `page_cache_sync_readahead` in `generic_file_buffered_read`).
//! Pre-D31 `File::read`/`read_iter` bypassed `f_ra` entirely. These prove a
//! `read`/`readv` on a regular file drives the window state, that the returned
//! byte count is still bounded by the buffer (no over-read), and that a
//! non-regular inode does not touch the window.

use std::sync::Arc;
use std::sync::Mutex;

use vfs::file::FileRaState;
use vfs::inode::Inode;
use vfs::mapping::AddressSpaceOps;
use vfs::{
    default_inode_ops, mk_mode, Dentry, File, FileOps, FileType, InodeBuilder, InodeRef, KResult,
    OpenFlags,
};

struct RegOps;
impl FileOps for RegOps {
    fn read(&self, _i: &Inode, _o: u64, b: &mut [u8]) -> KResult<usize> { Ok(b.len()) }
}

/// Records the readahead windows the read path submits. Before the window was
/// wired to the address space, `ra_ondemand`'s answer was bound to `let _` at
/// every call site, so this list stayed empty no matter what `f_ra` said.
#[derive(Default)]
struct RaSpy { windows: Mutex<Vec<(u64, u64)>> }
impl AddressSpaceOps for RaSpy {
    fn shared_frame(&self, _off: u64) -> KResult<Option<vfs::mapping::SharedFrame>> { Ok(None) }
    fn read_at(&self, _off: u64, dst: &mut [u8]) -> KResult<usize> { Ok(dst.len()) }
    fn size(&self) -> u64 { 1 << 30 }
    fn readahead(&self, start: u64, nr_pages: u64) {
        self.windows.lock().unwrap().push((start, nr_pages));
    }
}

fn file(ft: FileType) -> Arc<File> {
    let ino: InodeRef = InodeBuilder::new(
        11, mk_mode(ft, 0o644), default_inode_ops(), Arc::new(RegOps)).build();
    let d = Dentry::new(None, "f".into(), ino.clone());
    File::new(ino, d, OpenFlags::O_RDONLY)
}

fn spied_file() -> (Arc<File>, Arc<RaSpy>) {
    let spy = Arc::new(RaSpy::default());
    let m: Arc<dyn AddressSpaceOps> = spy.clone();
    let ino: InodeRef = InodeBuilder::new(
        13, mk_mode(FileType::Regular, 0o644), default_inode_ops(), Arc::new(RegOps))
        .mapping(m).build();
    let d = Dentry::new(None, "f".into(), ino.clone());
    (File::new(ino, d, OpenFlags::O_RDONLY), spy)
}

// The window is not just computed — it is SUBMITTED. This is what makes
// `posix_fadvise` hints observable: they only ever move `ra_pages`, and
// `ra_pages` only reaches the disk through this call.
#[test]
fn a_buffered_read_submits_its_readahead_window_to_the_address_space() {
    let (f, spy) = spied_file();
    let mut buf = [0u8; 4096];
    f.read(&mut buf).unwrap();
    let w = spy.windows.lock().unwrap().clone();
    assert_eq!(w.len(), 1, "one submit per read");
    let ra = f.ra_state();
    assert_eq!(w[0], (ra.start, ra.size as u64), "the submitted window IS f_ra's");
    assert!(w[0].1 > 0);
}

// `POSIX_FADV_SEQUENTIAL` doubles `ra_pages` and `POSIX_FADV_RANDOM` zeroes it.
// Both were inert: the ceiling moved and nothing read it into a fill.
#[test]
fn fadvise_hints_change_the_window_that_is_actually_submitted() {
    let (seq, seq_spy) = spied_file();
    seq.ra_set_sequential();
    let mut buf = [0u8; 4096];
    seq.read(&mut buf).unwrap();
    let big = seq_spy.windows.lock().unwrap()[0].1;

    let (nrm, nrm_spy) = spied_file();
    nrm.ra_set_normal();
    nrm.read(&mut buf).unwrap();
    let normal = nrm_spy.windows.lock().unwrap()[0].1;
    assert!(big >= normal, "SEQUENTIAL submits at least the NORMAL window");

    let (rnd, rnd_spy) = spied_file();
    rnd.ra_set_random();
    rnd.read(&mut buf).unwrap();
    assert!(rnd_spy.windows.lock().unwrap().is_empty(),
        "FADV_RANDOM submits no readahead at all");
}

// The generic `AddressSpaceOps::readahead` default must populate without
// copying anything out to a caller, and must skip resident pages and stop at
// i_size.
#[test]
fn the_generic_readahead_default_fills_pages_and_stops_at_eof() {
    #[derive(Default)]
    struct Counting { reads: Mutex<Vec<u64>> }
    impl AddressSpaceOps for Counting {
        fn shared_frame(&self, _off: u64) -> KResult<Option<vfs::mapping::SharedFrame>> { Ok(None) }
        fn read_at(&self, off: u64, dst: &mut [u8]) -> KResult<usize> {
            self.reads.lock().unwrap().push(off);
            Ok(dst.len())
        }
        fn size(&self) -> u64 { 3 * 4096 }
    }
    let c = Counting::default();
    c.readahead(0, 8);
    assert_eq!(*c.reads.lock().unwrap(), vec![0, 4096, 8192],
        "clamped to i_size; never reads past the last page");
}

#[test]
fn buffered_read_advances_ra_window() {
    let f = file(FileType::Regular);
    assert_eq!(f.ra_state().size, 0, "window empty before any read");
    let mut buf = [0u8; 4096];
    let n = f.read(&mut buf).unwrap();
    assert_eq!(n, 4096, "read returns exactly the buffer length (no over-read)");
    let ra = f.ra_state();
    assert!(ra.size > 0, "buffered read seeded the readahead window");
    assert_eq!(ra.size, FileRaState::init_ra_size(1, ra.ra_pages),
        "initial window is get_init_ra_size(req=1)");
}

#[test]
fn sequential_reads_grow_window() {
    let f = file(FileType::Regular);
    let mut buf = [0u8; 4096];
    f.read(&mut buf).unwrap();
    let first = f.ra_state().size;
    // Continue sequentially across the window for several pages.
    for _ in 0..6 { f.read(&mut buf).unwrap(); }
    assert!(f.ra_state().size >= first, "sequential reads grow (or hold) the window");
}

#[test]
fn vectored_read_advances_window() {
    let f = file(FileType::Regular);
    let mut a = [0u8; 4096];
    let mut b = [0u8; 4096];
    {
        let mut bufs: [&mut [u8]; 2] = [&mut a, &mut b];
        f.read_iter(&mut bufs).unwrap();
    }
    assert!(f.ra_state().size > 0, "vectored read seeded the window");
}

#[test]
fn non_regular_inode_leaves_window_untouched() {
    // A FIFO is not a readahead target; the window must stay empty.
    let ino: InodeRef = InodeBuilder::new(
        12, mk_mode(FileType::Fifo, 0o644), default_inode_ops(), Arc::new(RegOps)).build();
    let d = Dentry::new(None, "p".into(), ino.clone());
    let f = File::new(ino, d, OpenFlags::O_RDONLY);
    let mut buf = [0u8; 4096];
    f.read(&mut buf).unwrap();
    assert_eq!(f.ra_state().size, 0, "non-regular read does not drive readahead");
}
