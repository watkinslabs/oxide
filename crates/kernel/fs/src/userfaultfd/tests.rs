// Hosted tests for the non-parking userfaultfd logic: API/REGISTER
// return codes + range recording, event enqueue → `read` drain, and
// UNREGISTER removal. The park/COPY-map path needs a live AS + runqueue
// and is boot-verified, not hosted.
//
// The ioctls write their output fields back THROUGH the `arg` raw
// pointer; the test reads those fields back with `read_volatile` (a
// plain `arr[i]` read would be constant-folded to the pre-call value
// because the write went through a provenance-erased `as u64` cast).

use super::*;
use vmm::UffdContext;

const UFFDIO_API:        u64 = 0xc018_aa3f;
const UFFDIO_REGISTER:   u64 = 0xc020_aa00;
const UFFDIO_UNREGISTER: u64 = 0x8010_aa01;
const MODE_MISSING:      u64 = 1 << 0;

fn ufd_of(inode: &InodeRef) -> Arc<UfData> {
    inode.i_private().clone().downcast::<UfData>().expect("UfData")
}

/// Read back word `i` of an ioctl arg buffer after the call. # C: O(1)
fn word(buf: &[u64], i: usize) -> u64 {
    // SAFETY: `i` is in-bounds of `buf`; the ioctl wrote through the same
    // aligned pointer, so a volatile read reloads the committed value.
    unsafe { core::ptr::read_volatile(buf.as_ptr().add(i)) }
}

#[test]
fn api_sets_features_zero_and_marks_api() {
    let inode = make_userfaultfd_inode(0);
    let api = [0xAAu64, 0xBBu64]; // { api, features }
    let rv = handle_uffd_ioctl(&inode, UFFDIO_API, api.as_ptr() as u64);
    assert_eq!(rv, 0);
    assert_eq!(word(&api, 1), 0, "features must negotiate to 0");
    assert!(ufd_of(&inode).state.lock().api_set);
}

#[test]
fn register_records_range_and_reports_ioctls() {
    let inode = make_userfaultfd_inode(0);
    let start = 0x1_0000u64;
    let len   = 0x2000u64;
    // UffdioRegister { range{start,len}, mode, ioctls }
    let reg = [start, len, MODE_MISSING, 0u64];
    let rv = handle_uffd_ioctl(&inode, UFFDIO_REGISTER, reg.as_ptr() as u64);
    assert_eq!(rv, 0);
    assert_ne!(word(&reg, 3), 0, "ioctls bitmap must be reported");
    let d = ufd_of(&inode);
    let g = d.state.lock();
    assert_eq!(g.ranges.len(), 1);
    assert_eq!(g.ranges[0].start, start);
    assert_eq!(g.ranges[0].end, start + len);
}

#[test]
fn register_rejects_unaligned_and_zero_mode() {
    let inode = make_userfaultfd_inode(0);
    let bad_align = [0x1001u64, 0x2000, MODE_MISSING, 0];
    assert!(handle_uffd_ioctl(&inode, UFFDIO_REGISTER, bad_align.as_ptr() as u64) < 0);
    let zero_mode = [0x1_0000u64, 0x2000, 0, 0];
    assert!(handle_uffd_ioctl(&inode, UFFDIO_REGISTER, zero_mode.as_ptr() as u64) < 0);
    assert_eq!(ufd_of(&inode).state.lock().ranges.len(), 0);
}

#[test]
fn enqueued_pagefault_msg_drains_through_read() {
    let inode = make_userfaultfd_inode(0);
    let d = ufd_of(&inode);
    let addr = 0xDEAD_0000u64;
    // missing_fault under hosted enqueues + returns (no park).
    d.missing_fault(addr, true);
    assert_eq!(d.state.lock().events.len(), 1);
    let mut buf = [0u8; 32];
    let n = UffdFileOps.read(&inode, 0, &mut buf).expect("read event");
    assert_eq!(n, 32);
    // Decode the 32-byte uffd_msg.
    assert_eq!(buf[0], UFFD_EVENT_PAGEFAULT);
    // ABI byte layout (Linux `uffd_msg.arg.pagefault`): flags@8, address@16.
    let got_flags = u64::from_ne_bytes(buf[8..16].try_into().unwrap());
    let got_addr = u64::from_ne_bytes(buf[16..24].try_into().unwrap());
    assert_eq!(got_addr, addr);
    assert_eq!(got_flags & UFFD_PAGEFAULT_FLAG_WRITE, UFFD_PAGEFAULT_FLAG_WRITE);
    // Queue now empty → poll reports not-readable.
    assert_eq!(UffdFileOps.poll(&inode), 0);
}

#[test]
fn read_empty_nonblock_is_eagain() {
    let inode = make_userfaultfd_inode(0);
    let mut buf = [0u8; 32];
    assert_eq!(UffdFileOps.read_nonblock(&inode, 0, &mut buf), Err(vfs::VfsError::Eagain));
}

#[test]
fn unregister_removes_range() {
    let inode = make_userfaultfd_inode(0);
    let start = 0x1_0000u64;
    let len   = 0x2000u64;
    let reg = [start, len, MODE_MISSING, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_REGISTER, reg.as_ptr() as u64), 0);
    let unreg = [start, len]; // UffdioRange
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_UNREGISTER, unreg.as_ptr() as u64), 0);
    assert_eq!(ufd_of(&inode).state.lock().ranges.len(), 0);
}
