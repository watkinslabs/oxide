// The four mode-specific commands end-to-end through the dispatcher, over a
// real address space: WRITEPROTECT, CONTINUE, POISON and MOVE.
//
// The page work itself is target-gated (see `work/hosted.rs`); what these
// exercise is everything around it — which registration a command demands,
// which errno each refusal carries, and what lands in the reply word.

use alloc::sync::Arc;

use hal::UserVirtAddr;
use syscall::errno::Errno;
use vfs::InodeRef;
use vmm::{AddressSpace, UffdContext, UffdFaultKind, VmaBacking, VmaFlags, VmaProt};

use crate::userfaultfd::msg::kind_flag;
use crate::userfaultfd::uapi::*;
use crate::userfaultfd::{handle_uffd_ioctl, make_userfaultfd_inode, UfData};

const PAGE: u64 = hal::PAGE_SIZE_BYTES;
const REGION: u64 = 0x1_0000;
const REGION_LEN: u64 = 8 * PAGE;
/// A second anonymous region, for the move destination.
const REGION2: u64 = 0x20_0000;

fn e(err: Errno) -> i64 { -(err.as_i32() as i64) }

fn word(buf: &[u64], i: usize) -> u64 {
    // SAFETY: `i` is in-bounds of `buf`; the ioctl wrote through the same aligned pointer, so a volatile read reloads the committed value.
    unsafe { core::ptr::read_volatile(buf.as_ptr().add(i)) }
}

fn ufd_of(inode: &InodeRef) -> Arc<UfData> {
    inode.i_private().clone().downcast::<UfData>().expect("UfData")
}

fn mk_mm() -> Arc<AddressSpace> {
    let mm = AddressSpace::new(0).expect("AS::new");
    for base in [REGION, REGION2] {
        mm.mmap(Some(UserVirtAddr::new(base).expect("va")), REGION_LEN as usize,
            VmaProt::READ | VmaProt::WRITE,
            VmaFlags::PRIVATE | VmaFlags::ANONYMOUS,
            VmaBacking::Anonymous, true).expect("mmap");
    }
    mm
}

/// An fd bound to `mm`, past the handshake, registered over `REGION` with
/// `mode`.
fn mk_registered(mm: &Arc<AddressSpace>, mode: u64) -> InodeRef {
    let inode = make_userfaultfd_inode(0, Arc::downgrade(mm));
    let api = [UFFD_API, 0u64, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_API, api.as_ptr() as u64), 0);
    let reg = [REGION, REGION_LEN, mode, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_REGISTER, reg.as_ptr() as u64), 0);
    inode
}

// ---- UFFDIO_WRITEPROTECT --------------------------------------------------

/// Protecting a range the context did not register for WP is ENOENT: it is not
/// a bad argument, it is a request about memory this monitor does not own.
#[test]
fn write_protect_requires_a_wp_registration() {
    let mm = mk_mm();
    let missing_only = mk_registered(&mm, UFFDIO_REGISTER_MODE_MISSING);
    let wp = [REGION, REGION_LEN, UFFDIO_WRITEPROTECT_MODE_WP];
    assert_eq!(handle_uffd_ioctl(&missing_only, UFFDIO_WRITEPROTECT, wp.as_ptr() as u64),
               e(Errno::Enoent));

    let mm2 = mk_mm();
    let armed = mk_registered(&mm2, UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_WP);
    assert_eq!(handle_uffd_ioctl(&armed, UFFDIO_WRITEPROTECT, wp.as_ptr() as u64), 0);
    // Resolving the same range is the inverse and equally accepted.
    let resolve = [REGION, REGION_LEN, 0u64];
    assert_eq!(handle_uffd_ioctl(&armed, UFFDIO_WRITEPROTECT, resolve.as_ptr() as u64), 0);
}

#[test]
fn write_protect_validates_its_range_and_mode_word() {
    let mm = mk_mm();
    let inode = mk_registered(&mm, UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_WP);
    let unaligned = [REGION + 1, PAGE, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_WRITEPROTECT, unaligned.as_ptr() as u64),
               e(Errno::Einval));
    let both = [REGION, PAGE, UFFDIO_WRITEPROTECT_MODE_WP | UFFDIO_WRITEPROTECT_MODE_DONTWAKE];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_WRITEPROTECT, both.as_ptr() as u64),
               e(Errno::Einval));
    let unknown = [REGION, PAGE, 1u64 << 4];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_WRITEPROTECT, unknown.as_ptr() as u64),
               e(Errno::Einval));
    // A range extending past the registered VMA reaches unregistered memory.
    let past = [REGION, REGION_LEN + PAGE, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_WRITEPROTECT, past.as_ptr() as u64),
               e(Errno::Enoent));
}

/// Resolving the barrier releases the threads it stopped. Arming it has nobody
/// to release, so it must not bump the wake generation — a spurious wake would
/// send every blocked faulter round the loop for nothing.
#[test]
fn only_a_resolve_wakes_blocked_faulters() {
    let mm = mk_mm();
    let inode = mk_registered(&mm, UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_WP);
    let d = ufd_of(&inode);
    let before = d.wake_generation();
    let arm = [REGION, PAGE, UFFDIO_WRITEPROTECT_MODE_WP];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_WRITEPROTECT, arm.as_ptr() as u64), 0);
    assert_eq!(d.wake_generation(), before, "arming the barrier must not wake");
    let resolve = [REGION, PAGE, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_WRITEPROTECT, resolve.as_ptr() as u64), 0);
    assert_ne!(d.wake_generation(), before, "resolving must release the faulters");
    let quiet = [REGION, PAGE, UFFDIO_WRITEPROTECT_MODE_DONTWAKE];
    let after = d.wake_generation();
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_WRITEPROTECT, quiet.as_ptr() as u64), 0);
    assert_eq!(d.wake_generation(), after, "DONTWAKE must suppress the wake");
}

// ---- UFFDIO_CONTINUE ------------------------------------------------------

/// A continue publishes a page the backing already holds. Anonymous memory has
/// no such backing, so the command is refused rather than accepted and left to
/// fail invisibly per page.
#[test]
fn continue_is_refused_on_a_mapping_with_no_backing() {
    let mm = mk_mm();
    let inode = mk_registered(&mm, UFFDIO_REGISTER_MODE_MISSING);
    let k = [REGION, PAGE, 0u64, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_CONTINUE, k.as_ptr() as u64), e(Errno::Einval));
    assert_eq!(word(&k, 3) as i64, e(Errno::Einval), "the reply word carries the errno");
}

#[test]
fn continue_obeys_the_shared_destination_ladder() {
    let mm = mk_mm();
    let inode = mk_registered(&mm, UFFDIO_REGISTER_MODE_MISSING);
    let outside = REGION + 0x100_0000;
    let nowhere = [outside, PAGE, 0u64, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_CONTINUE, nowhere.as_ptr() as u64),
               e(Errno::Enoent));
    let bad_mode = [REGION, PAGE, 1u64 << 3, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_CONTINUE, bad_mode.as_ptr() as u64),
               e(Errno::Einval));
}

// ---- UFFDIO_POISON --------------------------------------------------------

#[test]
fn poison_marks_the_registered_range_and_reports_the_byte_count() {
    let mm = mk_mm();
    let inode = mk_registered(&mm, UFFDIO_REGISTER_MODE_MISSING);
    let p = [REGION, 2 * PAGE, 0u64, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_POISON, p.as_ptr() as u64), 0);
    assert_eq!(word(&p, 3), 2 * PAGE);
}

/// Poisoning is a way to make memory unusable, so it goes through the same
/// destination ladder as every other fill: a monitor may only poison memory it
/// registered.
#[test]
fn poison_cannot_reach_memory_this_context_did_not_register() {
    let mm = mk_mm();
    let inode = mk_registered(&mm, UFFDIO_REGISTER_MODE_MISSING);
    let elsewhere = [REGION2, PAGE, 0u64, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_POISON, elsewhere.as_ptr() as u64),
               e(Errno::Enoent));
    let nowhere = [REGION + 0x100_0000, PAGE, 0u64, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_POISON, nowhere.as_ptr() as u64),
               e(Errno::Enoent));
    let bad_mode = [REGION, PAGE, 1u64 << 1, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_POISON, bad_mode.as_ptr() as u64),
               e(Errno::Einval));
}

// ---- UFFDIO_MOVE ----------------------------------------------------------

#[test]
fn move_requires_the_destination_to_be_registered_here() {
    let mm = mk_mm();
    // Registered over REGION; REGION2 belongs to nobody.
    let inode = mk_registered(&mm, UFFDIO_REGISTER_MODE_MISSING);
    let into_unregistered = [REGION2, REGION, PAGE, 0u64, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_MOVE, into_unregistered.as_ptr() as u64),
               e(Errno::Einval));
    // The other direction — into the registered region, out of the unregistered
    // one — is exactly what a move is for.
    let ok = [REGION, REGION2, PAGE, 0u64, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_MOVE, ok.as_ptr() as u64), 0);
    assert_eq!(word(&ok, 4), PAGE);
}

#[test]
fn move_validates_both_ranges_and_its_mode_word() {
    let mm = mk_mm();
    let inode = mk_registered(&mm, UFFDIO_REGISTER_MODE_MISSING);
    let unaligned_src = [REGION, REGION2 + 1, PAGE, 0u64, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_MOVE, unaligned_src.as_ptr() as u64),
               e(Errno::Einval));
    let nowhere = [REGION, REGION + 0x100_0000, PAGE, 0u64, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_MOVE, nowhere.as_ptr() as u64), e(Errno::Enoent));
    let bad_mode = [REGION, REGION2, PAGE, 1u64 << 2, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_MOVE, bad_mode.as_ptr() as u64), e(Errno::Einval));
    // Past the source VMA's end.
    let past = [REGION, REGION2, REGION_LEN + PAGE, 0u64, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_MOVE, past.as_ptr() as u64), e(Errno::Einval));
}

/// The fd is bound to the address space captured at creation. Once that space
/// is gone every range op reports ESRCH rather than resolving against whoever
/// holds the fd now.
#[test]
fn every_mode_command_reports_esrch_once_the_address_space_is_gone() {
    let mm = mk_mm();
    let inode = mk_registered(&mm, UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_WP);
    drop(mm);
    let wp = [REGION, PAGE, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_WRITEPROTECT, wp.as_ptr() as u64), e(Errno::Esrch));
    let p = [REGION, PAGE, 0u64, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_POISON, p.as_ptr() as u64), e(Errno::Esrch));
    let k = [REGION, PAGE, 0u64, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_CONTINUE, k.as_ptr() as u64), e(Errno::Esrch));
    let mv = [REGION, REGION2, PAGE, 0u64, 0u64];
    assert_eq!(handle_uffd_ioctl(&inode, UFFDIO_MOVE, mv.as_ptr() as u64), e(Errno::Esrch));
}

// ---- message flags --------------------------------------------------------

/// A monitor registered for several modes tells the faults apart by the flag
/// alone. If two kinds carried the same flag it would resolve one with the
/// wrong command and hang.
#[test]
fn each_fault_kind_carries_its_own_message_flag() {
    assert_eq!(kind_flag(UffdFaultKind::Missing), 0);
    assert_eq!(kind_flag(UffdFaultKind::Wp), UFFD_PAGEFAULT_FLAG_WP);
    assert_eq!(kind_flag(UffdFaultKind::Minor), UFFD_PAGEFAULT_FLAG_MINOR);
    assert_ne!(UFFD_PAGEFAULT_FLAG_WP, UFFD_PAGEFAULT_FLAG_MINOR);
    assert_eq!(UFFD_PAGEFAULT_FLAG_WRITE & (UFFD_PAGEFAULT_FLAG_WP | UFFD_PAGEFAULT_FLAG_MINOR), 0);
}

/// Every kind is delivered through the one queue, and the message says which
/// kind it was.
#[test]
fn every_fault_kind_is_delivered_through_the_same_queue() {
    let mm = mk_mm();
    let inode = mk_registered(&mm, UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_WP);
    let d = ufd_of(&inode);
    for (kind, write, want) in [
        (UffdFaultKind::Missing, false, 0u64),
        (UffdFaultKind::Wp, true, UFFD_PAGEFAULT_FLAG_WP | UFFD_PAGEFAULT_FLAG_WRITE),
        (UffdFaultKind::Minor, false, UFFD_PAGEFAULT_FLAG_MINOR),
    ] {
        assert!(d.fault(REGION, kind, write, true));
        let m = d.state.lock().faults.pop_front().expect("fault");
        assert_eq!(m.event, UFFD_EVENT_PAGEFAULT);
        assert_eq!(m.addr(), REGION);
        assert_eq!(m.flags(), want, "{kind:?} must carry its own flags");
    }
}
