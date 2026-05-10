// Hosted unit tests covering the v1 BlockDevice + PageCache surface
// per `17§9`. Multi-CPU writeback / dirty-list / async-completion
// tests land alongside their respective impls in follow-ups.

extern crate alloc;
use super::*;
use crate::blockdev::{BlockDevice, BlockRequest, MemDisk};
use crate::pagecache::{CachedPage, PageCache};
use crate::types::{BlockError, BlockOp, InodeId, PageFlags, PAGE_BYTES};

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use sync::Inode as InodeClass;

type Disk = MemDisk<InodeClass>;

// ---------------------------------------------------------------------------
// MemDisk / BlockDevice
// ---------------------------------------------------------------------------

#[test]
fn memdisk_capacity_matches_construction() {
    let d = Disk::new(512, 64);
    assert_eq!(d.block_size(), 512);
    assert_eq!(d.capacity_blocks(), 64);
}

#[test]
fn memdisk_read_zero_initialized() {
    let d = Disk::new(512, 4);
    let mut req = BlockRequest::new_read(0, 4, 512);
    d.submit_sync(&mut req).unwrap();
    assert_eq!(req.buffer.len(), 4 * 512);
    assert!(req.buffer.iter().all(|&b| b == 0));
}

#[test]
fn memdisk_write_then_read_roundtrip() {
    let d = Disk::new(512, 4);
    let payload: Vec<u8> = (0..2048u32).map(|i| i as u8).collect();
    let mut w = BlockRequest::new_write(0, 4, payload.clone());
    d.submit_sync(&mut w).unwrap();
    let mut r = BlockRequest::new_read(0, 4, 512);
    d.submit_sync(&mut r).unwrap();
    assert_eq!(r.buffer, payload);
}

#[test]
fn memdisk_oob_access_returns_eio() {
    let d = Disk::new(512, 4);
    let mut req = BlockRequest::new_read(8, 1, 512);
    assert_eq!(d.submit_sync(&mut req), Err(BlockError::Eio));
}

#[test]
fn memdisk_discard_zeros_range() {
    let d = Disk::new(512, 4);
    let payload = vec![0xAA; 1024];
    let mut w = BlockRequest::new_write(0, 2, payload);
    d.submit_sync(&mut w).unwrap();
    let mut disc = BlockRequest {
        op: BlockOp::Discard, start_block: 0, len_blocks: 1, buffer: Vec::new(),
    };
    d.submit_sync(&mut disc).unwrap();
    let mut r = BlockRequest::new_read(0, 2, 512);
    d.submit_sync(&mut r).unwrap();
    assert!(r.buffer[..512].iter().all(|&b| b == 0));   // discarded
    assert!(r.buffer[512..].iter().all(|&b| b == 0xAA)); // untouched
}

// ---------------------------------------------------------------------------
// PageCache lookup / read_page / write_page / fsync / invalidate
// ---------------------------------------------------------------------------

#[test]
fn pagecache_empty_lookup_miss() {
    let pc = PageCache::new();
    assert!(pc.lookup(InodeId(1), 0).is_none());
    assert_eq!(pc.cached_count(), 0);
}

#[test]
fn pagecache_read_page_hits_cache_after_first_load() {
    let d = Disk::new(512, 8 * (PAGE_BYTES as u64 / 512) as u64);
    // Pre-populate disk with a known pattern.
    let payload: Vec<u8> = (0..PAGE_BYTES as u32).map(|i| (i & 0xFF) as u8).collect();
    let mut w = BlockRequest::new_write(0, (PAGE_BYTES / 512) as u32, payload.clone());
    d.submit_sync(&mut w).unwrap();

    let pc = PageCache::new();
    let p1 = pc.read_page(InodeId(1), 0, &*d).unwrap();
    let p2 = pc.read_page(InodeId(1), 0, &*d).unwrap();
    assert!(Arc::ptr_eq(&p1, &p2), "second read must be a cache hit");
    assert_eq!(*p1.data.lock(), payload);
    assert_eq!(pc.cached_count(), 1);
    assert!(p1.flags().contains(PageFlags::UPTODATE));
}

#[test]
fn pagecache_unaligned_offset_is_einval() {
    let d = Disk::new(512, 8);
    let pc = PageCache::new();
    assert_eq!(
        pc.read_page(InodeId(1), 1, &*d).err(),
        Some(BlockError::Einval),
    );
}

#[test]
fn pagecache_write_marks_dirty() {
    let d = Disk::new(512, (PAGE_BYTES / 512) as u64 * 2);
    let pc = PageCache::new();
    let payload = vec![0x5A; PAGE_BYTES];
    let p = pc.write_page(InodeId(1), 0, &payload, &*d).unwrap();
    assert!(p.is_dirty(), "write_page must mark PG_DIRTY");
    assert_eq!(*p.data.lock(), payload);
    // Disk untouched until fsync.
    let mut r = BlockRequest::new_read(0, (PAGE_BYTES / 512) as u32, 512);
    d.submit_sync(&mut r).unwrap();
    assert!(r.buffer.iter().all(|&b| b == 0));
}

#[test]
fn pagecache_fsync_writes_dirty_pages_then_clears_flag() {
    let d = Disk::new(512, (PAGE_BYTES / 512) as u64 * 4);
    let pc = PageCache::new();
    let payload = vec![0xC3; PAGE_BYTES];
    let p = pc.write_page(InodeId(1), 0, &payload, &*d).unwrap();
    assert!(p.is_dirty());
    pc.fsync(InodeId(1), &*d).unwrap();
    assert!(!p.is_dirty(), "fsync must clear PG_DIRTY");
    // Disk now reflects the write.
    let mut r = BlockRequest::new_read(0, (PAGE_BYTES / 512) as u32, 512);
    d.submit_sync(&mut r).unwrap();
    assert_eq!(r.buffer, payload);
}

#[test]
fn pagecache_fsync_only_flushes_target_inode() {
    let d = Disk::new(512, (PAGE_BYTES / 512) as u64 * 4);
    let pc = PageCache::new();
    let p1 = pc.write_page(InodeId(1), 0, &vec![1; PAGE_BYTES], &*d).unwrap();
    // Inode 2 lives on different disk pages (1 page in).
    let p2 = pc.write_page(
        InodeId(2),
        PAGE_BYTES as u64,
        &vec![2; PAGE_BYTES],
        &*d,
    ).unwrap();
    assert!(p1.is_dirty() && p2.is_dirty());
    pc.fsync(InodeId(1), &*d).unwrap();
    assert!(!p1.is_dirty(), "inode 1 fsynced");
    assert!(p2.is_dirty(),  "inode 2 untouched");
}

#[test]
fn pagecache_invalidate_drops_pages_for_inode() {
    let d = Disk::new(512, (PAGE_BYTES / 512) as u64 * 4);
    let pc = PageCache::new();
    let _ = pc.read_page(InodeId(1), 0, &*d).unwrap();
    let _ = pc.read_page(InodeId(2), 0, &*d).unwrap();
    assert_eq!(pc.cached_count(), 2);
    pc.invalidate(InodeId(1));
    assert_eq!(pc.cached_count(), 1);
    assert!(pc.lookup(InodeId(1), 0).is_none());
    assert!(pc.lookup(InodeId(2), 0).is_some());
}

#[test]
fn pagecache_multi_inode_isolation() {
    let d = Disk::new(512, (PAGE_BYTES / 512) as u64 * 4);
    let pc = PageCache::new();
    let p1 = pc.write_page(InodeId(1), 0, &vec![1; PAGE_BYTES], &*d).unwrap();
    let p2 = pc.write_page(InodeId(2), 0, &vec![2; PAGE_BYTES], &*d).unwrap();
    assert_ne!(*p1.data.lock(), *p2.data.lock());
    let look_1 = pc.lookup(InodeId(1), 0).unwrap();
    let look_2 = pc.lookup(InodeId(2), 0).unwrap();
    assert!(Arc::ptr_eq(&look_1, &p1));
    assert!(Arc::ptr_eq(&look_2, &p2));
}

#[test]
fn cached_page_flag_set_clear_round_trip() {
    let p = CachedPage::new(InodeId(0), 0, vec![0; PAGE_BYTES]);
    assert!(p.flags().contains(PageFlags::UPTODATE));
    let prev = p.set_flags(PageFlags::DIRTY);
    assert!(prev.contains(PageFlags::UPTODATE));
    assert!(p.flags().contains(PageFlags::DIRTY));
    p.clear_flags(PageFlags::DIRTY);
    assert!(!p.flags().contains(PageFlags::DIRTY));
}

#[test]
fn pagecache_concurrent_readers_share_one_page() {
    use std::sync::Arc as StdArc;
    use std::thread;
    let d = StdArc::new(Disk::new(512, (PAGE_BYTES / 512) as u64 * 4));
    let pc: StdArc<PageCache> = StdArc::new(PageCache::new());
    let mut handles = Vec::new();
    for _ in 0..8 {
        let pc = StdArc::clone(&pc);
        let d = StdArc::clone(&d);
        handles.push(thread::spawn(move || {
            let p = pc.read_page(InodeId(7), 0, &**d).unwrap();
            Arc::as_ptr(&p) as usize
        }));
    }
    let ptrs: Vec<usize> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    // Every reader saw the same Arc identity.
    let first = ptrs[0];
    assert!(ptrs.iter().all(|&p| p == first), "concurrent readers diverged: {ptrs:?}");
    assert_eq!(pc.cached_count(), 1);
}
