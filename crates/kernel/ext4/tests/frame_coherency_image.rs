//! D8 ext4 frame-backed page-cache coherency, against the real mini.img.
//!
//! Proves the three views of one inode (read(2), write(2), MAP_SHARED mmap)
//! all alias ONE per-inode PMM frame store:
//!   * read == write: a write(2) is visible to a later read(2).
//!   * mmap == read:  a store into the MAP_SHARED frame is visible to read(2),
//!     and read(2)'s page IS the shared frame.
//!   * writeback persists: a frame mutation flushed by `i_mapping().writeback()`
//!     survives a remount of the same device.
//!
//! All paths run through the SAME inode (`iget` shared identity via a
//! back-stamped SuperBlock), which is the kernel's coherency guarantee: one
//! inode → one `i_mapping` → one frame store.

extern crate alloc;
mod common;

use alloc::string::String;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::fs::FileSystem;
use vfs::SuperBlock;

const IMAGE: &[u8] = include_bytes!("mini.img");
const SECTOR: u32 = 512;
const PG: usize = 4096;

/// A MemDisk preloaded with mini.img; returned as the concrete `Arc<MemDisk>`
/// so a remount can reopen the SAME backing store (persistence check).
fn fresh_disk() -> Arc<MemDisk<TaskList>> {
    let cap = (IMAGE.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest {
        op: BlockOp::Write, start_block: 0, len_blocks: cap as u32, buffer: IMAGE.to_vec(),
    };
    disk.submit_sync(&mut req).unwrap();
    disk
}

/// Open `disk` as an ext4 mount with a back-stamped SuperBlock so `wrap_file`
/// returns the SAME inode `Arc` across calls (Linux `iget`). The returned
/// `Arc<SuperBlock>` MUST be kept alive (the mount holds only a `Weak`).
fn open_with_sb(disk: Arc<dyn BlockDevice>) -> (Arc<ext4::rootfs::Ext4Mount>, Arc<SuperBlock>) {
    let m = ext4::rootfs::Ext4Mount::open(disk).unwrap();
    let fs: Arc<dyn FileSystem> = m.clone();
    let root = fs.root();
    let sb = common::realize_sb(fs.clone(), root, 0x1234_5678, String::from("ext4"));
    (m, sb)
}

#[test]
fn one_inode_two_handles_share_frame_store() {
    common::boot_hosted_pmm();
    let (m, _sb) = open_with_sb(fresh_disk());
    let ino = m.state().lookup_path(b"/hello.txt").expect("hello.txt");

    let a = m.state().wrap_file(ino).expect("wrap a");
    let b = m.state().wrap_file(ino).expect("wrap b");
    assert!(Arc::ptr_eq(&a, &b), "iget returns the SAME inode Arc (one frame store)");

    // Both expose the same MAP_SHARED frame for page 0 (one cache).
    let fa = a.i_mapping().unwrap().shared_frame(0).expect("frame a");
    let fb = b.i_mapping().unwrap().shared_frame(0).expect("frame b");
    assert_eq!(fa, fb, "both handles hand out the SAME inode frame");
}

#[test]
fn write_is_visible_to_read() {
    common::boot_hosted_pmm();
    let (m, _sb) = open_with_sb(fresh_disk());
    let ino = m.state().lookup_path(b"/hello.txt").expect("hello.txt");
    let f = m.state().wrap_file(ino).expect("wrap");

    // Overwrite the first bytes in-place (within the existing first block).
    let pat = b"OXIDE-D8";
    let n = f.write(0, pat).expect("write");
    assert_eq!(n, pat.len());

    let mut buf = [0u8; 8];
    let r = f.read(0, &mut buf).expect("read");
    assert_eq!(r, pat.len(), "read returns the written length");
    assert_eq!(&buf, pat, "read(2) observes the write(2) (one coherent cache)");
}

#[test]
fn buffered_growth_is_visible_before_writeback() {
    // A new SQLite database writes its header before the first fsync. Its
    // immediate reread must use the in-core i_size and resident page, rather
    // than the old zero-length ext4 inode on disk.
    common::boot_hosted_pmm();
    let (m, _sb) = open_with_sb(fresh_disk());
    let st = m.state();
    let db = st.create_at(b"/sqlite-new.db", 0o644).expect("create database");
    let hdr = b"SQLite format 3\0";
    assert_eq!(db.write(0, hdr).expect("buffered header write"), hdr.len());
    assert_eq!(db.size(), hdr.len() as u64, "VFS i_size advances before writeback");

    let mut got = [0u8; 16];
    assert_eq!(db.read(0, &mut got).expect("reread buffered header"), hdr.len());
    assert_eq!(&got[..hdr.len()], hdr, "read(2) sees the new SQLite header before fsync");
}

#[test]
fn mmap_store_is_visible_to_read_and_shares_the_frame() {
    common::boot_hosted_pmm();
    let (m, _sb) = open_with_sb(fresh_disk());
    let ino = m.state().lookup_path(b"/hello.txt").expect("hello.txt");
    let f = m.state().wrap_file(ino).expect("wrap");

    // Fault page 0 in for read (resident frame).
    let mut pre = [0u8; 4];
    f.read(0, &mut pre).expect("read pre");

    // A MAP_SHARED mapping's frame for page 0.
    let pa = f.i_mapping().unwrap().shared_frame(0).expect("shared frame").expect("resident shared frame").pa;
    // The read path serves from the SAME frame: store through the frame (what a
    // userspace mmap write does via the CPU), then read(2) must see it.
    let pat = [0xDEu8, 0xAD, 0xBE, 0xEF];
    let base = pmm::setup::frame_ptr(pa).expect("frame_ptr");
    // SAFETY: pa is the inode's resident page-0 frame; 4-byte write in-bounds.
    unsafe { core::ptr::copy_nonoverlapping(pat.as_ptr(), base, pat.len()); }

    let mut buf = [0u8; 4];
    f.read(0, &mut buf).expect("read post");
    assert_eq!(buf, pat, "read(2) observes the MAP_SHARED store — read IS the shared frame");
}

#[test]
fn multipage_frame_read_matches_legacy_and_source_b240() {
    common::boot_hosted_pmm();
    let disk = fresh_disk();
    let dev: Arc<dyn BlockDevice> = disk.clone();

    // A multi-page, non-page-aligned payload: spans several ext4 blocks and >2
    // pages, with a partial final page (the B240 short-fill-at-EOF case).
    let total = 2 * PG + 1234;
    let mut pat = alloc::vec![0u8; total];
    for (i, b) in pat.iter_mut().enumerate() { *b = (i as u32).wrapping_mul(2654435761).to_le_bytes()[0]; }

    // Create + write the file, flush to disk, drop the mount.
    {
        let (m, _sb) = open_with_sb(dev.clone());
        let st = m.state();
        let root = st.lookup_path(b"/").expect("root");
        let new_ino = st.mount.create_file(root, b"big.bin", 0o644, 0, 0).expect("create big.bin");
        let f = st.wrap_file(new_ino).expect("wrap big.bin");
        // Write in a few chunks crossing page boundaries.
        let mut off = 0usize;
        for chunk in [4000usize, 200, total - 4200] {
            f.write(off as u64, &pat[off..off + chunk]).expect("write chunk");
            off += chunk;
        }
        f.i_mapping().unwrap().writeback().expect("writeback");
    }

    // Fresh remount: no resident frames, so the frame read fills purely from
    // disk. Compare the frame path (inode.read → read_framed) to the legacy Vec
    // page-cache path (RootfsState::read_cached) and to the source bytes.
    let (m2, _sb2) = open_with_sb(dev.clone());
    let ino = m2.state().lookup_path(b"/big.bin").expect("big.bin after remount");
    let f = m2.state().wrap_file(ino).expect("wrap big.bin remount");

    let mut via_frame = alloc::vec![0u8; total];
    let n1 = f.read(0, &mut via_frame).expect("frame read");
    assert_eq!(n1, total, "frame read returns full length");
    assert_eq!(&via_frame[..], &pat[..], "frame read == source bytes (B240 multi-page fill)");

    let mut via_legacy = alloc::vec![0u8; total];
    let n2 = m2.state().read_cached(ino, 0, &mut via_legacy).expect("legacy read");
    assert_eq!(n2, total, "legacy read returns full length");
    assert_eq!(&via_frame[..], &via_legacy[..], "frame read byte-identical to legacy Vec page-cache read");

    // Short read past EOF: reading at total-10 with a big buffer returns 10.
    let mut tail = [0u8; 64];
    let nt = f.read((total - 10) as u64, &mut tail).expect("tail read");
    assert_eq!(nt, 10, "short read clamps at EOF");
    assert_eq!(&tail[..10], &pat[total - 10..], "EOF tail bytes correct");
}

#[test]
fn buffered_growing_write_persists_full_extent_across_remount() {
    // The size-authority path: a buffered write(2) grows the file WELL past its
    // on-disk i_size across several pages. Writeback must flush the whole new
    // extent (clamped to the in-memory size, not the stale on-disk size) or the
    // tail is silently truncated. Flush is driven by inode/mount Drop only (no
    // explicit writeback) — proves the durability-on-eviction path too.
    common::boot_hosted_pmm();
    let disk = fresh_disk();
    let dev: Arc<dyn BlockDevice> = disk.clone();

    let total = 3 * PG + 777; // multi-page, partial final page
    let mut pat = alloc::vec![0u8; total];
    for (i, b) in pat.iter_mut().enumerate() { *b = (i as u32).wrapping_mul(2246822519).to_le_bytes()[1]; }

    {
        let (m, _sb) = open_with_sb(dev.clone());
        let st = m.state();
        let root = st.lookup_path(b"/").expect("root");
        let ino = st.mount.create_file(root, b"grow.bin", 0o644, 0, 0).expect("create grow.bin");
        let f = st.wrap_file(ino).expect("wrap grow.bin");
        // One buffered write extends 0 -> total across pages. No writeback call:
        // rely on Drop flushing dirty pages at eviction.
        let n = f.write(0, &pat).expect("buffered write");
        assert_eq!(n, total, "write returns full length");
        assert_eq!(f.size(), total as u64, "i_size reflects the buffered growth immediately");
        // mount + sb + inode drop here → Drop flushes dirty frames.
    }

    let (m2, _sb2) = open_with_sb(dev.clone());
    let ino2 = m2.state().lookup_path(b"/grow.bin").expect("grow.bin after remount");
    let f2 = m2.state().wrap_file(ino2).expect("wrap after remount");
    assert_eq!(f2.size(), total as u64, "on-disk i_size == full buffered size after flush");
    let mut got = alloc::vec![0u8; total];
    let r = f2.read(0, &mut got).expect("read after remount");
    assert_eq!(r, total, "reads the full extent back");
    assert_eq!(&got[..], &pat[..], "every byte of the grown file persisted (no tail truncation)");
}

#[test]
fn buffered_partial_overwrite_preserves_untouched_bytes() {
    // Partial-page RMW: overwrite bytes in the MIDDLE of an existing file via a
    // buffered write. The untouched head/tail of the page must be faulted in
    // from disk and survive the flush (Linux read-modify-write of a partial
    // page), not be zeroed.
    common::boot_hosted_pmm();
    let disk = fresh_disk();
    let dev: Arc<dyn BlockDevice> = disk.clone();

    let base_len = PG + 500;
    let mut base = alloc::vec![0u8; base_len];
    for (i, b) in base.iter_mut().enumerate() { *b = (i as u8).wrapping_add(1); }

    {
        let (m, _sb) = open_with_sb(dev.clone());
        let st = m.state();
        let root = st.lookup_path(b"/").expect("root");
        let ino = st.mount.create_file(root, b"rmw.bin", 0o644, 0, 0).expect("create rmw.bin");
        let f = st.wrap_file(ino).expect("wrap rmw.bin");
        f.write(0, &base).expect("write base");
        f.i_mapping().unwrap().writeback().expect("flush base");
        // Now overwrite an 8-byte middle span crossing no page boundary.
        let patch = *b"MIDPATCH";
        f.write(1000, &patch).expect("buffered middle overwrite");
        base[1000..1008].copy_from_slice(&patch);
        f.i_mapping().unwrap().writeback().expect("flush patch");
    }

    let (m2, _sb2) = open_with_sb(dev.clone());
    let ino2 = m2.state().lookup_path(b"/rmw.bin").expect("rmw.bin after remount");
    let f2 = m2.state().wrap_file(ino2).expect("wrap after remount");
    let mut got = alloc::vec![0u8; base_len];
    f2.read(0, &mut got).expect("read after remount");
    assert_eq!(&got[..], &base[..], "middle overwrite applied, surrounding bytes preserved");
}

#[test]
fn writeback_persists_across_remount() {
    common::boot_hosted_pmm();
    let disk = fresh_disk();
    let dev: Arc<dyn BlockDevice> = disk.clone();

    let pat = [0x55u8, 0xAA, 0x55, 0xAA, 0x12, 0x34];
    {
        let (m, _sb) = open_with_sb(dev.clone());
        let ino = m.state().lookup_path(b"/hello.txt").expect("hello.txt");
        let f = m.state().wrap_file(ino).expect("wrap");

        // Mutate via the MAP_SHARED frame (no write(2) write-through), then flush.
        let pa = f.i_mapping().unwrap().shared_frame(0).expect("shared frame").expect("resident shared frame").pa;
        let base = pmm::setup::frame_ptr(pa).expect("frame_ptr");
        // SAFETY: pa is the inode's resident page-0 frame; write in-bounds.
        unsafe { core::ptr::copy_nonoverlapping(pat.as_ptr(), base, pat.len()); }
        f.i_mapping().unwrap().writeback().expect("writeback");
        // mount + sb + inode drop here.
    }

    // Remount the SAME device: the flushed bytes must be on disk.
    let (m2, _sb2) = open_with_sb(dev.clone());
    let ino2 = m2.state().lookup_path(b"/hello.txt").expect("hello.txt after remount");
    let f2 = m2.state().wrap_file(ino2).expect("wrap after remount");
    let mut buf = [0u8; 6];
    f2.read(0, &mut buf).expect("read after remount");
    assert_eq!(buf, pat, "writeback persisted the frame mutation across remount");
    let _ = PG; // silence if unused in some cfg
}

#[test]
fn shared_mapping_after_truncate_persists_across_batched_remount() {
    // SQLite's new-database sequence: create an empty file, ftruncate it to
    // page-sized storage, populate those pages through MAP_SHARED, then fsync.
    // The root filesystem keeps metadata in a running journal transaction, so
    // this must also remain correct with cross-operation batching enabled.
    common::boot_hosted_pmm();
    let disk = fresh_disk();
    let dev: Arc<dyn BlockDevice> = disk.clone();
    let payload = *b"SQLite format 3\0";

    {
        let (m, _sb) = open_with_sb(dev.clone());
        let st = m.state();
        st.mount.begin_batch();
        let root = st.lookup_path(b"/").expect("root");
        let ino = st.mount.create_file(root, b"sqlite-mmap.db", 0o644, 0, 0)
            .expect("create sqlite database");
        let f = st.wrap_file(ino).expect("wrap sqlite database");

        f.truncate((2 * PG) as u64).expect("ftruncate two pages");
        let pa0 = f.i_mapping().unwrap().shared_frame(0).expect("map page zero");
        let pa1 = f.i_mapping().unwrap().shared_frame(PG as u64).expect("map page one");
        let base0 = pmm::setup::frame_ptr(pa0.pa).expect("page zero pointer");
        let base1 = pmm::setup::frame_ptr(pa1.pa).expect("page one pointer");
        // Linux ftruncate growth is zero-filled even when the final logical
        // page gets a real ext4 block. A freed block's former directory bytes
        // must never become visible merely because it was selected for EOF.
        let before0 = unsafe { core::slice::from_raw_parts(base0, PG) };
        let before1 = unsafe { core::slice::from_raw_parts(base1, PG) };
        assert!(before0.iter().all(|&b| b == 0), "first grown page is zero-filled");
        assert!(before1.iter().all(|&b| b == 0), "last grown page is zero-filled");
        // SAFETY: both are inode-owned MAP_SHARED frames and the writes stay
        // within their 4 KiB page bounds.
        unsafe {
            core::ptr::copy_nonoverlapping(payload.as_ptr(), base0, payload.len());
            core::ptr::write_bytes(base1, 0xA5, PG);
        }
        f.i_mapping().unwrap().writeback().expect("fsync writeback");
        st.mount.commit_batch().expect("commit root-style transaction");
    }

    let (m2, _sb2) = open_with_sb(dev);
    let ino = m2.state().lookup_path(b"/sqlite-mmap.db").expect("database after remount");
    let f = m2.state().wrap_file(ino).expect("wrap database after remount");
    let mut got = [0u8; 16];
    assert_eq!(f.read(0, &mut got).expect("read sqlite header"), got.len());
    assert_eq!(&got[..payload.len()], &payload, "mapped first page persisted");
    let mut second = [0u8; 16];
    assert_eq!(f.read(PG as u64, &mut second).expect("read second page"), second.len());
    assert_eq!(second, [0xA5; 16], "mapped second page persisted");
}

#[test]
fn shared_mapping_over_unwritten_extent_persists_across_batched_remount() {
    // `posix_fallocate` users (including database engines) receive unwritten
    // extents. A MAP_SHARED store must convert those extents to written data at
    // writeback; returning the physical preallocation bytes would expose stale
    // directory/file contents instead of the Linux zero-fill contract.
    common::boot_hosted_pmm();
    let disk = fresh_disk();
    let dev: Arc<dyn BlockDevice> = disk.clone();
    let payload = *b"SQLite format 3\0";

    {
        let (m, _sb) = open_with_sb(dev.clone());
        let st = m.state();
        st.mount.begin_batch();
        let root = st.lookup_path(b"/").expect("root");
        let ino = st.mount.create_file(root, b"sqlite-fallocate.db", 0o644, 0, 0)
            .expect("create sqlite database");
        st.mount.fallocate_inode(ino, 0, (2 * PG) as u64, false)
            .expect("fallocate two unwritten pages");
        let f = st.wrap_file(ino).expect("wrap sqlite database");

        let pa0 = f.i_mapping().unwrap().shared_frame(0).expect("map page zero");
        let pa1 = f.i_mapping().unwrap().shared_frame(PG as u64).expect("map page one");
        let base0 = pmm::setup::frame_ptr(pa0.pa).expect("page zero pointer");
        let base1 = pmm::setup::frame_ptr(pa1.pa).expect("page one pointer");
        // SAFETY: both are inode-owned MAP_SHARED frames and the writes stay
        // within their 4 KiB page bounds.
        unsafe {
            core::ptr::copy_nonoverlapping(payload.as_ptr(), base0, payload.len());
            core::ptr::write_bytes(base1, 0x5A, PG);
        }
        f.i_mapping().unwrap().writeback().expect("fsync writeback");
        st.mount.commit_batch().expect("commit root-style transaction");
    }

    let (m2, _sb2) = open_with_sb(dev);
    let ino = m2.state().lookup_path(b"/sqlite-fallocate.db").expect("database after remount");
    let f = m2.state().wrap_file(ino).expect("wrap database after remount");
    let mut got = [0u8; 16];
    assert_eq!(f.read(0, &mut got).expect("read sqlite header"), got.len());
    assert_eq!(&got[..payload.len()], &payload, "mapped first page persisted");
    let mut second = [0u8; 16];
    assert_eq!(f.read(PG as u64, &mut second).expect("read second page"), second.len());
    assert_eq!(second, [0x5A; 16], "mapped second page persisted");
}
