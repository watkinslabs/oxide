// The cooperative half end-to-end over a REAL `vmm::AddressSpace`: the
// registrations a fork carries (and the ones it must not), the announcements
// each address-space change queues, and the refusal every resolve runs into
// while one is outstanding.
//
// The block a live generator takes is absent hosted, so each test observes the
// state a parked generator leaves behind: the announcement queued and the
// charge outstanding. That is exactly the window the refusal exists for.

use alloc::sync::Arc;

use hal::UserVirtAddr;
use syscall::errno::Errno;
use vfs::InodeRef;
use vmm::{AddressSpace, UffdContext, UffdEvent, UffdEventKind, VmaBacking, VmaFlags, VmaProt};

use crate::userfaultfd::uapi::*;
use crate::userfaultfd::{handle_uffd_ioctl, make_userfaultfd_inode, UfData};

const PAGE: u64 = hal::PAGE_SIZE_BYTES;
const REGION: u64 = 0x1_0000;
const REGION_LEN: u64 = 8 * PAGE;

fn e(err: Errno) -> i64 { -(err.as_i32() as i64) }

fn ufd_of(inode: &InodeRef) -> Arc<UfData> {
    inode.i_private().clone().downcast::<UfData>().expect("UfData")
}

fn mk_mm() -> Arc<AddressSpace> {
    let mm = AddressSpace::new(0).expect("AS::new");
    mm.mmap(Some(UserVirtAddr::new(REGION).expect("va")), REGION_LEN as usize,
        VmaProt::READ | VmaProt::WRITE,
        VmaFlags::PRIVATE | VmaFlags::ANONYMOUS,
        VmaBacking::Anonymous, true).expect("mmap");
    mm
}

/// An fd on `mm` whose monitor negotiated `features`, with the region
/// registered for missing faults.
///
/// The fork feature's capability gate reads the RUNNING task, of which there is
/// none here, so that one feature is installed on the context directly. The
/// gate itself is covered where it belongs, over the handshake ladder.
fn mk_ctx(mm: &Arc<AddressSpace>, features: u64) -> InodeRef {
    let inode = make_userfaultfd_inode(0, Arc::downgrade(mm));
    let negotiable = features & !feature::EVENT_FORK;
    let api = [UFFD_API, negotiable, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_API, api.as_ptr() as u64), 0,
               "handshake for {negotiable:#x}");
    if features & feature::EVENT_FORK != 0 {
        ufd_of(&inode).features.store(features | feature::INITIALIZED,
                                      core::sync::atomic::Ordering::Release);
    }
    let reg = [REGION, REGION_LEN, UFFDIO_REGISTER_MODE_MISSING, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_REGISTER, reg.as_ptr() as u64), 0);
    inode
}

/// The one queued announcement, as `(event, a0, a1, a2)`.
fn one_event(d: &Arc<UfData>) -> (u8, u64, u64, u64) {
    let g = d.state.lock();
    assert_eq!(g.events.len(), 1, "exactly one announcement");
    let ev = g.events.front().expect("announcement");
    (ev.event, ev.a0, ev.a1, ev.a2)
}

// ---- fork -----------------------------------------------------------------

/// A monitor that tracks forks gets a registration in the CHILD, covering the
/// same range with the same modes, bound to a DIFFERENT context — the two
/// address spaces resolve independently from here on — and exactly one
/// announcement.
#[test]
fn a_fork_tracking_monitor_gets_a_separate_context_in_the_child() {
    let mm = mk_mm();
    let inode = mk_ctx(&mm, feature::EVENT_FORK);
    let parent = ufd_of(&inode);
    let child_mm = mm.fork(0).expect("fork");

    let va = UserVirtAddr::new(REGION).expect("va");
    let hit = child_mm.uffd_for(va).expect("the child carries the registration");
    assert_eq!(hit.modes, VmaFlags::UFFD_MISSING);
    let parent_ctx: Arc<dyn UffdContext> = parent.clone();
    assert!(!Arc::ptr_eq(&hit.ctx, &parent_ctx),
            "the child must not share the parent's context");

    let (event, ..) = one_event(&parent);
    assert_eq!(event, UFFD_EVENT_FORK);
}

/// A monitor that did NOT ask about forks gets nothing in the child: no
/// registration, no announcement, and no charge. Carrying the registration over
/// would hand it faults from a process it has no record of.
#[test]
fn a_monitor_that_does_not_track_forks_gets_nothing_in_the_child() {
    let mm = mk_mm();
    let inode = mk_ctx(&mm, 0);
    let parent = ufd_of(&inode);
    let child_mm = mm.fork(0).expect("fork");

    assert!(child_mm.uffd_for(UserVirtAddr::new(REGION).expect("va")).is_none());
    assert_eq!(parent.state.lock().events.len(), 0);
    assert_eq!(parent.changes_in_flight(), 0);
}

/// One announcement per fork, however many VMAs the registration spans. A
/// second context is not minted for the second VMA either — the child's whole
/// registration is one context, as the parent's is.
#[test]
fn a_registration_spanning_two_vmas_still_forks_as_one_context() {
    let mm = mk_mm();
    // Split the region in two by re-protecting its second half.
    let mid = REGION + REGION_LEN / 2;
    mm.mprotect(UserVirtAddr::new(mid).expect("va"), (REGION_LEN / 2) as usize,
                VmaProt::READ).expect("mprotect");
    let inode = mk_ctx(&mm, feature::EVENT_FORK);
    let parent = ufd_of(&inode);
    let child_mm = mm.fork(0).expect("fork");

    let a = child_mm.uffd_for(UserVirtAddr::new(REGION).expect("va")).expect("first half");
    let b = child_mm.uffd_for(UserVirtAddr::new(mid).expect("va")).expect("second half");
    assert!(Arc::ptr_eq(&a.ctx, &b.ctx), "one child context for the whole registration");
    assert_eq!(parent.state.lock().events.len(), 1, "one announcement per fork");
}



// ---- range changes --------------------------------------------------------

/// The range-scoped charge covers every distinct monitor over the range, once
/// each, and the announcement carries the range's bounds.
#[test]
fn a_range_change_charges_each_monitor_once_and_announces_the_range() {
    let mm = mk_mm();
    let inode = mk_ctx(&mm, feature::EVENT_UNMAP);
    let d = ufd_of(&inode);
    let end = REGION + REGION_LEN;

    let watchers = mm.uffd_change_begin(REGION, end, UffdEventKind::Unmap);
    assert_eq!(watchers.len(), 1, "one charge per distinct monitor");
    assert_eq!(d.changes_in_flight(), 1);

    vmm::address_space::uffd::uffd_change_complete(
        watchers, UffdEvent::Unmap { start: REGION, end });
    let (event, start, stop, _) = one_event(&d);
    assert_eq!(event, UFFD_EVENT_UNMAP);
    assert_eq!((start, stop), (REGION, end));
}

/// The event a range change announces is gated by its own feature: a monitor
/// tracking unmaps is not charged for removals, and vice versa.
#[test]
fn a_range_change_only_charges_the_monitors_that_track_that_change() {
    let mm = mk_mm();
    let inode = mk_ctx(&mm, feature::EVENT_UNMAP);
    let d = ufd_of(&inode);
    let end = REGION + REGION_LEN;

    assert!(mm.uffd_change_begin(REGION, end, UffdEventKind::Remove).is_empty());
    assert_eq!(d.changes_in_flight(), 0);
    assert_eq!(mm.uffd_change_begin(REGION, end, UffdEventKind::Unmap).len(), 1);
}

/// A change outside the registered range charges nobody.
#[test]
fn a_change_outside_the_registered_range_charges_nobody() {
    let mm = mk_mm();
    let inode = mk_ctx(&mm, feature::EVENT_UNMAP);
    let d = ufd_of(&inode);
    let far = REGION + REGION_LEN;
    assert!(mm.uffd_change_begin(far, far + PAGE, UffdEventKind::Unmap).is_empty());
    assert_eq!(d.changes_in_flight(), 0);
}

// ---- the refusal ----------------------------------------------------------

/// Every resolve is refused while a change is outstanding, and each one that
/// owns a reply field reports the refusal THERE too — a monitor reads the
/// errno out of that word exactly as it reads a byte count out of a success.
#[test]
fn every_resolve_is_refused_while_a_change_is_outstanding() {
    let mm = mk_mm();
    let inode = mk_ctx(&mm, feature::EVENT_UNMAP);
    let d = ufd_of(&inode);
    d.charge_change();

    let copy = [REGION, REGION, PAGE, 0u64, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_COPY, copy.as_ptr() as u64), e(Errno::Eagain));
    assert_eq!(reply(&copy, 4), e(Errno::Eagain));

    let zero = [REGION, PAGE, 0u64, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_ZEROPAGE, zero.as_ptr() as u64), e(Errno::Eagain));
    assert_eq!(reply(&zero, 3), e(Errno::Eagain));

    let cont = [REGION, PAGE, 0u64, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_CONTINUE, cont.as_ptr() as u64), e(Errno::Eagain));
    assert_eq!(reply(&cont, 3), e(Errno::Eagain));

    let poison = [REGION, PAGE, 0u64, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_POISON, poison.as_ptr() as u64), e(Errno::Eagain));
    assert_eq!(reply(&poison, 3), e(Errno::Eagain));

    let mv = [REGION, REGION + PAGE, PAGE, 0u64, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_MOVE, mv.as_ptr() as u64), e(Errno::Eagain));
    assert_eq!(reply(&mv, 4), e(Errno::Eagain));

    let wp = [REGION, PAGE, UFFDIO_WRITEPROTECT_MODE_WP];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_WRITEPROTECT, wp.as_ptr() as u64),
               e(Errno::Eagain));
}

/// Write-protect has no reply field, which puts its refusal AHEAD of the
/// request object: EAGAIN wins over the fault an unreadable object would
/// produce. Every other range op has to write a reply word, so an unwritable
/// object is a fault first. The two orders are observable and are not the same.
#[test]
fn the_refusal_outranks_a_bad_request_object_only_where_nothing_is_written_back() {
    let mm = mk_mm();
    let inode = mk_ctx(&mm, feature::EVENT_UNMAP);
    let d = ufd_of(&inode);
    d.charge_change();
    // Address 0 is never a valid user object.
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_WRITEPROTECT, 0), e(Errno::Eagain));
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_COPY, 0), e(Errno::Efault));
}

/// Reading the announcement releases the charge, so the very next resolve is
/// admitted. A monitor's correct response to the refusal is to read its pending
/// event and reissue; if reading did not release, that loop would never end.
#[test]
fn reading_the_announcement_admits_the_next_resolve() {
    use vfs::FileOps;
    let mm = mk_mm();
    let inode = mk_ctx(&mm, feature::EVENT_UNMAP);
    let d = ufd_of(&inode);
    let end = REGION + REGION_LEN;

    let watchers = mm.uffd_change_begin(REGION, end, UffdEventKind::Unmap);
    vmm::address_space::uffd::uffd_change_complete(
        watchers, UffdEvent::Unmap { start: REGION, end });
    assert_eq!(d.changes_in_flight(), 1, "charged until the monitor reads it");
    let zero = [REGION, PAGE, 0u64, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_ZEROPAGE, zero.as_ptr() as u64),
               e(Errno::Eagain));

    let mut buf = [0u8; 32];
    let n = crate::userfaultfd::msg::UffdFileOps.read_nonblock(&inode, 0, &mut buf)
        .expect("the announcement reads out");
    assert_eq!(n, 32);
    assert_eq!(buf[0], UFFD_EVENT_UNMAP);
    assert_eq!(d.changes_in_flight(), 0);
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_ZEROPAGE, zero.as_ptr() as u64), 0);
}

/// A queued FAULT is read before a queued announcement. Reversing it starves
/// the fault a monitor must resolve to make progress behind the changes it is
/// being told about — and the thread holding that fault is one it is blocking.
#[test]
fn a_pending_fault_is_read_before_a_pending_announcement() {
    let mm = mk_mm();
    let inode = mk_ctx(&mm, feature::EVENT_UNMAP);
    let d = ufd_of(&inode);
    let end = REGION + REGION_LEN;

    let watchers = mm.uffd_change_begin(REGION, end, UffdEventKind::Unmap);
    vmm::address_space::uffd::uffd_change_complete(
        watchers, UffdEvent::Unmap { start: REGION, end });
    assert!(d.fault(REGION, vmm::UffdFaultKind::Missing, false, true));

    let mut buf = [0u8; 32];
    UffdFileOpsRead(&inode, &mut buf);
    assert_eq!(buf[0], UFFD_EVENT_PAGEFAULT, "the fault comes out first");
    UffdFileOpsRead(&inode, &mut buf);
    assert_eq!(buf[0], UFFD_EVENT_UNMAP);
}

/// A fork announcement that cannot hand its descriptor to the reader is put
/// BACK, still charged: losing it would strand the forking thread forever and
/// lose the child's context with it.
#[test]
fn a_fork_announcement_that_cannot_be_delivered_stays_queued() {
    use vfs::FileOps;
    let mm = mk_mm();
    let inode = mk_ctx(&mm, feature::EVENT_FORK);
    let d = ufd_of(&inode);
    let _child = mm.fork(0).expect("fork");
    assert_eq!(d.changes_in_flight(), 1);

    // Hosted there is no process to receive the descriptor, which is the same
    // arm the live path takes when the reader's table is full.
    let mut buf = [0u8; 32];
    assert!(crate::userfaultfd::msg::UffdFileOps.read_nonblock(&inode, 0, &mut buf).is_err());
    assert_eq!(d.state.lock().events.len(), 1, "the announcement is put back");
    assert_eq!(d.changes_in_flight(), 1, "and stays charged");
}

/// A poll reports readiness for an announcement, not only for a fault: a
/// monitor waiting in poll must wake for the change it is blocking.
#[test]
fn poll_reports_a_pending_announcement() {
    use vfs::FileOps;
    let mm = mk_mm();
    let inode = mk_ctx(&mm, feature::EVENT_UNMAP);
    let d = ufd_of(&inode);
    assert_eq!(crate::userfaultfd::msg::UffdFileOps.poll(&inode), 0);
    let end = REGION + REGION_LEN;
    let watchers = mm.uffd_change_begin(REGION, end, UffdEventKind::Unmap);
    vmm::address_space::uffd::uffd_change_complete(
        watchers, UffdEvent::Unmap { start: REGION, end });
    let _ = d;
    assert_eq!(crate::userfaultfd::msg::UffdFileOps.poll(&inode), vfs::POLL_IN);
}

/// Read back reply word `i` of an ioctl arg buffer. A plain index read would be
/// constant-folded to the pre-call value.
/// # C: O(1)
fn reply(buf: &[u64], i: usize) -> i64 {
    // SAFETY: `i` is in-bounds of `buf`; the ioctl wrote through the same aligned pointer, so a volatile read reloads the committed value.
    unsafe { core::ptr::read_volatile(buf.as_ptr().add(i)) as i64 }
}

/// One non-blocking read that must succeed. # C: O(1)
#[allow(non_snake_case)]
fn UffdFileOpsRead(inode: &InodeRef, buf: &mut [u8]) {
    use vfs::FileOps;
    crate::userfaultfd::msg::UffdFileOps.read_nonblock(inode, 0, buf).expect("a message reads out");
}
