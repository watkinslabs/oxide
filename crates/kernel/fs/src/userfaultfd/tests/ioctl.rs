// End-to-end `handle_uffd_ioctl` tests over a REAL `vmm::AddressSpace`.
//
// The ioctls write their output fields back THROUGH the `arg` raw pointer; the
// test reads those fields back with `read_volatile` (a plain `arr[i]` read
// would be constant-folded to the pre-call value because the write went
// through a provenance-erased `as u64` cast).

use alloc::sync::{Arc, Weak};

use hal::UserVirtAddr;
use syscall::errno::Errno;
use vfs::{FileOps, InodeRef};
use vmm::{AddressSpace, UffdContext, VmaBacking, VmaFlags, VmaProt};

use crate::userfaultfd::uapi::*;
use crate::userfaultfd::{handle_uffd_ioctl, make_userfaultfd_inode, UfData, UffdFileOps};

const PAGE: u64 = hal::PAGE_SIZE_BYTES;
/// Base of the anonymous region every test registers.
const REGION: u64 = 0x1_0000;
const REGION_LEN: u64 = 8 * PAGE;

fn ufd_of(inode: &InodeRef) -> Arc<UfData> {
    inode.i_private().clone().downcast::<UfData>().expect("UfData")
}

/// Read back word `i` of an ioctl arg buffer after the call. # C: O(1)
fn word(buf: &[u64], i: usize) -> u64 {
    // SAFETY: `i` is in-bounds of `buf`; the ioctl wrote through the same
    // aligned pointer, so a volatile read reloads the committed value.
    unsafe { core::ptr::read_volatile(buf.as_ptr().add(i)) }
}

/// A writable anonymous AS with `[REGION, REGION+REGION_LEN)` mapped.
fn mk_mm() -> Arc<AddressSpace> {
    let mm = AddressSpace::new(0).expect("AS::new");
    mm.mmap(Some(UserVirtAddr::new(REGION).expect("va")), REGION_LEN as usize,
        VmaProt::READ | VmaProt::WRITE,
        VmaFlags::PRIVATE | VmaFlags::ANONYMOUS,
        VmaBacking::Anonymous, true).expect("mmap");
    mm
}

/// Complete the `UFFDIO_API` handshake so the other commands are admitted.
fn handshake(inode: &InodeRef) {
    let api = [UFFD_API, 0u64, 0u64];
    assert_eq!(handle_uffd_ioctl(inode, UFFDIO_API, api.as_ptr() as u64), 0);
}

/// An fd bound to `mm`, past the handshake, with the region registered.
fn mk_registered(mm: &Arc<AddressSpace>) -> InodeRef {
    let inode = make_userfaultfd_inode(0, Arc::downgrade(mm));
    handshake(&inode);
    let reg = [REGION, REGION_LEN, UFFDIO_REGISTER_MODE_MISSING, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_REGISTER, reg.as_ptr() as u64), 0);
    inode
}

fn e(err: Errno) -> i64 { -(err.as_i32() as i64) }

// ---- handshake ordering ---------------------------------------------------

#[test]
fn every_command_before_the_api_handshake_is_einval() {
    let mm = mk_mm();
    let inode = make_userfaultfd_inode(0, Arc::downgrade(&mm));
    let reg = [REGION, REGION_LEN, UFFDIO_REGISTER_MODE_MISSING, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_REGISTER, reg.as_ptr() as u64), e(Errno::Einval));
    let cp = [REGION, REGION, PAGE, 0u64, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_COPY, cp.as_ptr() as u64), e(Errno::Einval));
}

#[test]
fn api_writes_the_ioctls_word_of_a_24_byte_object() {
    let mm = mk_mm();
    let inode = make_userfaultfd_inode(0, Arc::downgrade(&mm));
    let api = [UFFD_API, 0u64, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_API, api.as_ptr() as u64), 0);
    assert_eq!(word(&api, 1), UFFD_API_FEATURES);
    assert_eq!(word(&api, 2), UFFD_API_IOCTLS, "uffdio_api.ioctls must be reported");
    assert_ne!(word(&api, 2), 0);
}

#[test]
fn a_failed_api_zeroes_the_reply_object() {
    let mm = mk_mm();
    let inode = make_userfaultfd_inode(0, Arc::downgrade(&mm));
    let api = [0xBADu64, 0xF00Du64, 0xBEEFu64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_API, api.as_ptr() as u64), e(Errno::Einval));
    for i in 0..3 { assert_eq!(word(&api, i), 0, "err_out must memset uffdio_api"); }
}

#[test]
fn an_unknown_command_is_einval_not_enotty() {
    let mm = mk_mm();
    let inode = mk_registered(&mm);
    assert_eq!(handle_uffd_ioctl(&inode, 0xc020_aa07 /* UFFDIO_CONTINUE */, 0), e(Errno::Einval));
}

// ---- REGISTER -------------------------------------------------------------

#[test]
fn register_records_the_range_and_reports_the_linux_ioctl_bitmap() {
    let mm = mk_mm();
    let inode = make_userfaultfd_inode(0, Arc::downgrade(&mm));
    handshake(&inode);
    let reg = [REGION, REGION_LEN, UFFDIO_REGISTER_MODE_MISSING, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_REGISTER, reg.as_ptr() as u64), 0);
    assert_eq!(word(&reg, 3), (1 << slot::WAKE) | (1 << slot::COPY) | (1 << slot::ZEROPAGE));
    let d = ufd_of(&inode);
    let g = d.state.lock();
    assert_eq!(g.ranges.len(), 1);
    assert_eq!(g.ranges[0].start, REGION);
    assert_eq!(g.ranges[0].end, REGION + REGION_LEN);
}

#[test]
fn register_binds_the_context_to_the_ctx_mm_vmas() {
    let mm = mk_mm();
    let _inode = mk_registered(&mm);
    let v = mm.uffd_vma_at(UserVirtAddr::new(REGION).expect("va")).expect("vma");
    assert!(v.ctx.is_some(), "UFFDIO_REGISTER must install vm_userfaultfd_ctx");
    assert!(mm.maybe_uffd());
    // `find_vma` clones the VMA, and `Vma::clone` IS the fork-dup path, which
    // deliberately drops `uffd` — so it can never answer "is this registered?".
    // That is why the fill ladder uses `uffd_vma_at`; assert the trap exists so
    // a future reader does not "simplify" back onto `find_vma`.
    assert!(mm.find_vma(UserVirtAddr::new(REGION).expect("va")).expect("vma").uffd.is_none());
}

#[test]
fn register_refuses_wp_mode_instead_of_recording_a_dead_range() {
    let mm = mk_mm();
    let inode = make_userfaultfd_inode(0, Arc::downgrade(&mm));
    handshake(&inode);
    let reg = [REGION, REGION_LEN, UFFDIO_REGISTER_MODE_WP, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_REGISTER, reg.as_ptr() as u64), e(Errno::Einval));
    assert_eq!(ufd_of(&inode).state.lock().ranges.len(), 0);
    let v = mm.uffd_vma_at(UserVirtAddr::new(REGION).expect("va")).expect("vma");
    assert!(v.ctx.is_none());
}

#[test]
fn register_over_an_unmapped_range_is_einval() {
    let mm = mk_mm();
    let inode = make_userfaultfd_inode(0, Arc::downgrade(&mm));
    handshake(&inode);
    let hole = REGION + 0x100_0000;
    let reg = [hole, PAGE, UFFDIO_REGISTER_MODE_MISSING, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_REGISTER, reg.as_ptr() as u64), e(Errno::Einval));
    assert_eq!(ufd_of(&inode).state.lock().ranges.len(), 0);
}

#[test]
fn register_rejects_unaligned_and_zero_mode() {
    let mm = mk_mm();
    let inode = make_userfaultfd_inode(0, Arc::downgrade(&mm));
    handshake(&inode);
    let bad_align = [REGION + 1, PAGE, UFFDIO_REGISTER_MODE_MISSING, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_REGISTER, bad_align.as_ptr() as u64), e(Errno::Einval));
    let zero_mode = [REGION, PAGE, 0u64, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_REGISTER, zero_mode.as_ptr() as u64), e(Errno::Einval));
    assert_eq!(ufd_of(&inode).state.lock().ranges.len(), 0);
}

#[test]
fn unregister_removes_the_range_and_the_vma_binding() {
    let mm = mk_mm();
    let inode = mk_registered(&mm);
    let unreg = [REGION, REGION_LEN];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_UNREGISTER, unreg.as_ptr() as u64), 0);
    assert_eq!(ufd_of(&inode).state.lock().ranges.len(), 0);
    let v = mm.uffd_vma_at(UserVirtAddr::new(REGION).expect("va")).expect("vma");
    assert!(v.ctx.is_none());
}

// ---- COPY / ZEROPAGE destination enforcement ------------------------------

#[test]
fn copy_into_an_address_with_no_vma_is_refused() {
    // THE regression: before the destination ladder, this installed a fresh
    // USER|READ|WRITE page at an arbitrary address in the address space.
    let mm = mk_mm();
    let inode = mk_registered(&mm);
    let outside = REGION + 0x100_0000;
    let src = [0u8; 8];
    let cp = [outside, src.as_ptr() as u64, PAGE, 0u64, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_COPY, cp.as_ptr() as u64), e(Errno::Enoent));
    // Linux put_user()s the errno into `uffdio_copy.copy` on this path.
    assert_eq!(word(&cp, 4) as i64, e(Errno::Enoent));
    assert!(mm.find_vma(UserVirtAddr::new(outside).expect("va")).is_none());
}

#[test]
fn copy_into_a_mapped_but_unregistered_vma_is_refused() {
    let mm = mk_mm();
    let other = REGION + 0x20_0000;
    mm.mmap(Some(UserVirtAddr::new(other).expect("va")), (2 * PAGE) as usize,
        VmaProt::READ | VmaProt::WRITE, VmaFlags::PRIVATE | VmaFlags::ANONYMOUS,
        VmaBacking::Anonymous, true).expect("mmap");
    let inode = mk_registered(&mm);
    let src = [0u8; 8];
    let cp = [other, src.as_ptr() as u64, PAGE, 0u64, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_COPY, cp.as_ptr() as u64), e(Errno::Enoent));
}

#[test]
fn copy_running_past_the_registered_vma_end_is_refused() {
    let mm = mk_mm();
    let inode = mk_registered(&mm);
    let src = [0u8; 8];
    let cp = [REGION, src.as_ptr() as u64, REGION_LEN + PAGE, 0u64, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_COPY, cp.as_ptr() as u64), e(Errno::Enoent));
}

#[test]
fn copy_into_the_registered_range_succeeds_and_reports_the_byte_count() {
    let mm = mk_mm();
    let inode = mk_registered(&mm);
    let src = [0u8; 8];
    let cp = [REGION, src.as_ptr() as u64, 2 * PAGE, 0u64, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_COPY, cp.as_ptr() as u64), 0);
    assert_eq!(word(&cp, 4), 2 * PAGE);
}

#[test]
fn zeropage_obeys_the_same_destination_ladder() {
    let mm = mk_mm();
    let inode = mk_registered(&mm);
    let outside = REGION + 0x100_0000;
    let bad = [outside, PAGE, 0u64, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_ZEROPAGE, bad.as_ptr() as u64), e(Errno::Enoent));
    let good = [REGION, PAGE, 0u64, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_ZEROPAGE, good.as_ptr() as u64), 0);
    assert_eq!(word(&good, 3), PAGE);
}

#[test]
fn copy_targets_ctx_mm_so_a_dead_mm_is_esrch() {
    // The fd holds a WEAK reference to the address space captured at creation
    // (Linux `mmgrab` + `mmget_not_zero`). Dropping the AS makes every fill
    // report ESRCH — an implementation resolving against `current` instead
    // could not produce this.
    let mm = mk_mm();
    let inode = mk_registered(&mm);
    drop(mm);
    let src = [0u8; 8];
    let cp = [REGION, src.as_ptr() as u64, PAGE, 0u64, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_COPY, cp.as_ptr() as u64), e(Errno::Esrch));
}

#[test]
fn copy_rejects_a_bad_range_before_looking_at_the_destination() {
    let mm = mk_mm();
    let inode = mk_registered(&mm);
    let src = [0u8; 8];
    // Unaligned dst → EINVAL from validate_range, not ENOENT from the VMA scan.
    let cp = [REGION + 1, src.as_ptr() as u64, PAGE, 0u64, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_COPY, cp.as_ptr() as u64), e(Errno::Einval));
    // Unknown mode bit → EINVAL.
    let cp = [REGION, src.as_ptr() as u64, PAGE, 1u64 << 5, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_COPY, cp.as_ptr() as u64), e(Errno::Einval));
}

#[test]
fn wake_validates_its_range() {
    let mm = mk_mm();
    let inode = mk_registered(&mm);
    let bad = [REGION + 1, PAGE];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_WAKE, bad.as_ptr() as u64), e(Errno::Einval));
    let zero_len = [REGION, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_WAKE, zero_len.as_ptr() as u64), e(Errno::Einval));
    let good = [REGION, PAGE];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_WAKE, good.as_ptr() as u64), 0);
}

// ---- read / poll / fault delivery -----------------------------------------

#[test]
fn read_before_the_handshake_is_einval() {
    let mm = mk_mm();
    let inode = make_userfaultfd_inode(0, Arc::downgrade(&mm));
    let mut buf = [0u8; 32];
    assert_eq!(UffdFileOps.read(&inode, 0, &mut buf), Err(vfs::VfsError::Einval));
    assert_eq!(UffdFileOps.poll(&inode), vfs::POLL_ERR);
}

#[test]
fn enqueued_pagefault_msg_drains_through_read() {
    let mm = mk_mm();
    let inode = mk_registered(&mm);
    let d = ufd_of(&inode);
    let addr = REGION + PAGE;
    // missing_fault under hosted enqueues + returns (no park).
    assert!(d.missing_fault(addr, true, true));
    assert_eq!(d.state.lock().events.len(), 1);
    let mut buf = [0u8; 32];
    let n = UffdFileOps.read(&inode, 0, &mut buf).expect("read event");
    assert_eq!(n, 32);
    assert_eq!(buf[0], UFFD_EVENT_PAGEFAULT);
    // ABI byte layout (Linux `uffd_msg.arg.pagefault`): flags@8, address@16.
    let got_flags = u64::from_ne_bytes(buf[8..16].try_into().unwrap());
    let got_addr = u64::from_ne_bytes(buf[16..24].try_into().unwrap());
    assert_eq!(got_addr, addr);
    assert_eq!(got_flags & UFFD_PAGEFAULT_FLAG_WRITE, UFFD_PAGEFAULT_FLAG_WRITE);
    assert_eq!(UffdFileOps.poll(&inode), 0);
}

#[test]
fn read_empty_nonblock_is_eagain() {
    let mm = mk_mm();
    let inode = mk_registered(&mm);
    let mut buf = [0u8; 32];
    assert_eq!(UffdFileOps.read_nonblock(&inode, 0, &mut buf), Err(vfs::VfsError::Eagain));
}

#[test]
fn a_user_mode_only_context_refuses_a_kernel_mode_fault() {
    let mm = mk_mm();
    let inode = make_userfaultfd_inode(UFFD_USER_MODE_ONLY, Arc::downgrade(&mm));
    handshake(&inode);
    let d = ufd_of(&inode);
    assert!(!d.missing_fault(REGION, true, false), "kernel-mode fault must be refused");
    assert_eq!(d.state.lock().events.len(), 0, "a refused fault must not enqueue");
    assert!(d.missing_fault(REGION, true, true));
    assert_eq!(d.state.lock().events.len(), 1);
}

#[test]
fn a_dropped_context_reports_no_mm() {
    let mm = mk_mm();
    let inode = make_userfaultfd_inode(0, Weak::new());
    handshake(&inode);
    assert!(ufd_of(&inode).mm().is_none());
    drop(mm);
}
