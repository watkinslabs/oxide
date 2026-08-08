// The per-mode ladders: which VMAs each registration mode is legal on, what
// the registration promises, and how each resolve validates its request.
//
// The point of this module is that a mode is never accepted where it cannot
// deliver, and never promised where it was not requested.

use crate::userfaultfd::policy::*;
use crate::userfaultfd::uapi::*;
use syscall::errno::Errno;
use vmm::VmaFlags;

const PAGE: u64 = hal::PAGE_SIZE_BYTES;

/// A private anonymous mapping owned by no userfaultfd.
fn anon() -> RegVma {
    RegVma { anonymous: true, shmem: false, may_write: true, owned_by_other_uffd: false }
}
/// A memory-backed shared mapping.
fn shmem() -> RegVma {
    RegVma { anonymous: false, shmem: true, may_write: true, owned_by_other_uffd: false }
}

// ---- registration modes ---------------------------------------------------

#[test]
fn every_defined_mode_is_accepted_and_maps_to_its_vma_flag() {
    assert_eq!(check_register_mode(UFFDIO_REGISTER_MODE_MISSING), Ok(VmaFlags::UFFD_MISSING));
    assert_eq!(check_register_mode(UFFDIO_REGISTER_MODE_WP), Ok(VmaFlags::UFFD_WP));
    assert_eq!(check_register_mode(UFFDIO_REGISTER_MODE_MINOR), Ok(VmaFlags::UFFD_MINOR));
    assert_eq!(check_register_mode(UFFD_API_REGISTER_MODES),
               Ok(VmaFlags::UFFD_MISSING | VmaFlags::UFFD_WP | VmaFlags::UFFD_MINOR));
    assert_eq!(check_register_mode(0), Err(Errno::Einval));
    assert_eq!(check_register_mode(1 << 9), Err(Errno::Einval));
}

/// A mode may only be armed where the fault it intercepts can actually happen.
/// Accepting one elsewhere would register a barrier that silently does not
/// hold — worse than refusing, because the monitor would believe it.
#[test]
fn modes_are_refused_on_vmas_that_cannot_deliver_them() {
    let missing = VmaFlags::UFFD_MISSING;
    let wp = VmaFlags::UFFD_WP;
    let minor = VmaFlags::UFFD_MINOR;
    // Missing faults happen on both kinds of memory.
    assert!(vma_can_userfault(&anon(), missing));
    assert!(vma_can_userfault(&shmem(), missing));
    // A minor fault needs a backing that can already hold the page.
    assert!(vma_can_userfault(&shmem(), minor));
    assert!(!vma_can_userfault(&anon(), minor));
    // Write-protect state lives in a present anonymous leaf.
    assert!(vma_can_userfault(&anon(), wp));
    assert!(!vma_can_userfault(&shmem(), wp));
    // A mapping that is neither takes nothing at all.
    let other = RegVma { anonymous: false, shmem: false, may_write: true,
                         owned_by_other_uffd: false };
    for m in [missing, wp, minor] { assert!(!vma_can_userfault(&other, m)); }
    // A combination is legal only where EVERY member of it is.
    assert!(!vma_can_userfault(&anon(), missing | minor));
    assert!(!vma_can_userfault(&shmem(), missing | wp));
}

#[test]
fn register_vma_scan_enforces_maywrite_and_single_owner() {
    let m = VmaFlags::UFFD_MISSING;
    assert_eq!(check_register_vma(&anon(), m), Ok(()));
    assert_eq!(check_register_vma(&RegVma { anonymous: false, ..anon() }, m), Err(Errno::Einval));
    assert_eq!(check_register_vma(&RegVma { may_write: false, ..anon() }, m), Err(Errno::Eperm));
    assert_eq!(check_register_vma(&RegVma { owned_by_other_uffd: true, ..anon() }, m),
               Err(Errno::Ebusy));
    // Order: a VMA the mode is illegal on reports EINVAL even when it is also
    // unwritable and owned elsewhere.
    assert_eq!(check_register_vma(&RegVma { anonymous: false, shmem: false, may_write: false,
                                            owned_by_other_uffd: true }, m), Err(Errno::Einval));
}

/// The reply is a promise that the listed ops will succeed on this range, so a
/// mode-specific op must never appear without its mode.
#[test]
fn the_ioctls_reply_promises_only_the_requested_modes() {
    let missing = register_ioctls(UFFDIO_REGISTER_MODE_MISSING);
    assert_ne!(missing & (1 << slot::COPY), 0);
    assert_ne!(missing & (1 << slot::ZEROPAGE), 0);
    assert_ne!(missing & (1 << slot::WAKE), 0);
    assert_ne!(missing & (1 << slot::MOVE), 0);
    assert_ne!(missing & (1 << slot::POISON), 0);
    assert_eq!(missing & (1 << slot::WRITEPROTECT), 0, "WP promised without MODE_WP");
    assert_eq!(missing & (1 << slot::CONTINUE), 0, "CONTINUE promised without MODE_MINOR");
    assert_eq!(missing & (1 << slot::UNREGISTER), 0, "range reply must not list fd-level ops");

    let wp = register_ioctls(UFFDIO_REGISTER_MODE_WP);
    assert_ne!(wp & (1 << slot::WRITEPROTECT), 0);
    assert_eq!(wp & (1 << slot::CONTINUE), 0);

    let minor = register_ioctls(UFFDIO_REGISTER_MODE_MINOR);
    assert_ne!(minor & (1 << slot::CONTINUE), 0);
    assert_eq!(minor & (1 << slot::WRITEPROTECT), 0);

    assert_eq!(register_ioctls(UFFD_API_REGISTER_MODES), UFFD_API_RANGE_IOCTLS);
}

// ---- fill destination -----------------------------------------------------

fn dst_anon() -> DstVma {
    DstVma { end: 16 * PAGE, uffd_registered: true, uffd_wp: false, anonymous: true, shmem: false }
}
fn dst_shmem() -> DstVma {
    DstVma { end: 16 * PAGE, uffd_registered: true, uffd_wp: false, anonymous: false, shmem: true }
}

#[test]
fn a_fill_into_an_unmapped_or_unregistered_destination_is_refused() {
    assert_eq!(check_dst_vma(PAGE, None, false, FillKind::Copy), Err(Errno::Enoent));
    let unreg = DstVma { uffd_registered: false, ..dst_anon() };
    assert_eq!(check_dst_vma(PAGE, Some(unreg), false, FillKind::Copy), Err(Errno::Enoent));
    // Every kind uses the same ladder — including poison, which would otherwise
    // be a way to mark memory the caller does not own.
    for k in [FillKind::Copy, FillKind::Zeropage, FillKind::Continue, FillKind::Poison] {
        assert_eq!(check_dst_vma(PAGE, None, false, k), Err(Errno::Enoent));
        assert_eq!(check_dst_vma(PAGE, Some(unreg), false, k), Err(Errno::Enoent));
    }
}

#[test]
fn a_fill_running_past_the_vma_end_is_refused() {
    let v = DstVma { end: 4 * PAGE, ..dst_anon() };
    assert_eq!(check_dst_vma(4 * PAGE, Some(v), false, FillKind::Copy), Ok(()));
    assert_eq!(check_dst_vma(4 * PAGE + 1, Some(v), false, FillKind::Copy), Err(Errno::Enoent));
}

#[test]
fn a_write_protect_fill_reports_enoent_before_einval_at_an_unmapped_address() {
    assert_eq!(check_dst_vma(PAGE, None, true, FillKind::Copy), Err(Errno::Enoent));
    assert_eq!(check_dst_vma(PAGE, Some(dst_anon()), true, FillKind::Copy), Err(Errno::Einval));
    let wp = DstVma { uffd_wp: true, ..dst_anon() };
    assert_eq!(check_dst_vma(PAGE, Some(wp), true, FillKind::Copy), Ok(()));
}

/// A continue publishes a page the backing already holds. On a mapping with no
/// such backing there is nothing to continue, and accepting it would leave the
/// monitor waiting for a resolve that can never arrive.
#[test]
fn continue_requires_a_backing_that_can_hold_the_page() {
    assert_eq!(check_dst_vma(PAGE, Some(dst_shmem()), false, FillKind::Continue), Ok(()));
    assert_eq!(check_dst_vma(PAGE, Some(dst_anon()), false, FillKind::Continue), Err(Errno::Einval));
    // The other kinds are fine on both.
    for k in [FillKind::Copy, FillKind::Zeropage, FillKind::Poison] {
        assert_eq!(check_dst_vma(PAGE, Some(dst_anon()), false, k), Ok(()));
        assert_eq!(check_dst_vma(PAGE, Some(dst_shmem()), false, k), Ok(()));
    }
    // A registered mapping this kernel cannot fill at all is EINVAL, not a
    // silent success.
    let device = DstVma { anonymous: false, shmem: false, ..dst_anon() };
    assert_eq!(check_dst_vma(PAGE, Some(device), false, FillKind::Copy), Err(Errno::Einval));
}

#[test]
fn fill_mode_bits_are_per_command() {
    assert_eq!(check_copy_mode(UFFDIO_COPY_MODE_DONTWAKE | UFFDIO_COPY_MODE_WP), Ok(()));
    assert_eq!(check_copy_mode(1 << 5), Err(Errno::Einval));
    assert_eq!(check_zeropage_mode(UFFDIO_ZEROPAGE_MODE_DONTWAKE), Ok(()));
    assert_eq!(check_zeropage_mode(UFFDIO_COPY_MODE_WP), Err(Errno::Einval));
    assert_eq!(check_continue_mode(UFFDIO_CONTINUE_MODE_DONTWAKE | UFFDIO_CONTINUE_MODE_WP), Ok(()));
    assert_eq!(check_continue_mode(1 << 2), Err(Errno::Einval));
    assert_eq!(check_poison_mode(UFFDIO_POISON_MODE_DONTWAKE), Ok(()));
    assert_eq!(check_poison_mode(1 << 1), Err(Errno::Einval));
}

#[test]
fn short_fill_reports_eagain_not_enomem() {
    assert_eq!(fill_retval(2 * PAGE, 2 * PAGE, None), (0, 2 * PAGE as i64));
    let (rv, count) = fill_retval(PAGE, 2 * PAGE, Some(Errno::Enomem));
    assert_eq!(rv, -(Errno::Eagain.as_i32() as i64));
    assert_eq!(count, PAGE as i64);
    // Nothing installed → the reply field carries the negative errno and the
    // ioctl returns it.
    let (rv, count) = fill_retval(0, PAGE, Some(Errno::Eexist));
    assert_eq!(rv, -(Errno::Eexist.as_i32() as i64));
    assert_eq!(count, rv);
}

#[test]
fn dontwake_suppresses_the_wake_and_a_zero_fill_never_wakes() {
    assert!(should_wake(0, PAGE));
    assert!(!should_wake(UFFDIO_COPY_MODE_DONTWAKE, PAGE));
    assert!(!should_wake(0, 0));
}

// ---- write-protect --------------------------------------------------------

/// The two bits are assigned the opposite way round from every fill ioctl. A
/// shared "DONTWAKE is bit 0" assumption would invert this command silently:
/// arming the barrier when asked to resolve it.
#[test]
fn write_protect_mode_bits_are_not_the_fill_assignment() {
    assert_eq!(UFFDIO_WRITEPROTECT_MODE_WP, 1);
    assert_eq!(UFFDIO_WRITEPROTECT_MODE_DONTWAKE, 2);
    assert_eq!(check_wp_mode(UFFDIO_WRITEPROTECT_MODE_WP),
               Ok(WpMode { protect: true, dontwake: false }));
    assert_eq!(check_wp_mode(0), Ok(WpMode { protect: false, dontwake: false }));
    assert_eq!(check_wp_mode(UFFDIO_WRITEPROTECT_MODE_DONTWAKE),
               Ok(WpMode { protect: false, dontwake: true }));
    // Arming while suppressing the wake has no meaning: there are no faulters
    // to withhold a wake from.
    assert_eq!(check_wp_mode(UFFDIO_WRITEPROTECT_MODE_WP | UFFDIO_WRITEPROTECT_MODE_DONTWAKE),
               Err(Errno::Einval));
    assert_eq!(check_wp_mode(1 << 4), Err(Errno::Einval));
}

#[test]
fn write_protect_requires_every_vma_in_the_range_to_be_wp_registered() {
    let reg = |start, end| WpVma { start, end, uffd_wp: true };
    assert_eq!(check_wp_vma(0, 4 * PAGE, &[reg(0, 4 * PAGE)]), Ok(()));
    assert_eq!(check_wp_vma(0, 4 * PAGE, &[reg(0, 2 * PAGE), reg(2 * PAGE, 4 * PAGE)]), Ok(()));
    // An unregistered VMA in the range, a hole in the range, and an empty
    // range all mean "this context does not own that memory".
    assert_eq!(check_wp_vma(0, 4 * PAGE, &[WpVma { start: 0, end: 4 * PAGE, uffd_wp: false }]),
               Err(Errno::Enoent));
    assert_eq!(check_wp_vma(0, 4 * PAGE, &[reg(0, PAGE), reg(2 * PAGE, 4 * PAGE)]),
               Err(Errno::Enoent));
    assert_eq!(check_wp_vma(0, 4 * PAGE, &[]), Err(Errno::Enoent));
    assert_eq!(check_wp_vma(0, 4 * PAGE, &[reg(0, 2 * PAGE)]), Err(Errno::Enoent));
}

// ---- move -----------------------------------------------------------------

fn movable() -> MoveVma {
    MoveVma { start: 0, end: 16 * PAGE, prot: 0b11, write: true, shared: false, locked: false,
              anonymous: true, registered_by_this_ctx: true }
}

#[test]
fn move_mode_bits_follow_the_command() {
    assert_eq!(check_move_mode(0), Ok(MoveMode { allow_src_holes: false, dontwake: false }));
    assert_eq!(check_move_mode(UFFDIO_MOVE_MODE_ALLOW_SRC_HOLES),
               Ok(MoveMode { allow_src_holes: true, dontwake: false }));
    assert_eq!(check_move_mode(UFFDIO_MOVE_MODE_DONTWAKE),
               Ok(MoveMode { allow_src_holes: false, dontwake: true }));
    assert_eq!(check_move_mode(1 << 2), Err(Errno::Einval));
}

#[test]
fn move_ranges_must_lie_inside_two_private_mappings() {
    let (s, d) = (movable(), movable());
    assert_eq!(check_move_ranges(0, 0, 16 * PAGE, &s, &d), Ok(()));
    assert_eq!(check_move_ranges(0, 0, 17 * PAGE, &s, &d), Err(Errno::Einval));
    assert_eq!(check_move_ranges(0, 0, PAGE, &MoveVma { shared: true, ..s }, &d),
               Err(Errno::Einval));
    assert_eq!(check_move_ranges(0, 0, PAGE, &s, &MoveVma { shared: true, ..d }),
               Err(Errno::Einval));
    assert_eq!(check_move_ranges(0, 0, PAGE, &s, &MoveVma { end: PAGE / 2, ..d }),
               Err(Errno::Einval));
}

/// A moved page keeps its contents and its identity and only changes address,
/// so everything the move would otherwise have to re-decide must already match.
#[test]
fn move_refuses_any_pair_whose_properties_differ() {
    let (s, d) = (movable(), movable());
    assert_eq!(check_move_areas(&s, &d), Ok(()));
    assert_eq!(check_move_areas(&MoveVma { prot: 0b01, ..s }, &d), Err(Errno::Einval));
    assert_eq!(check_move_areas(&s, &MoveVma { locked: true, ..d }), Err(Errno::Einval));
    assert_eq!(check_move_areas(&MoveVma { write: false, ..s }, &d), Err(Errno::Einval));
    assert_eq!(check_move_areas(&MoveVma { anonymous: false, ..s }, &d), Err(Errno::Einval));
    assert_eq!(check_move_areas(&s, &MoveVma { anonymous: false, ..d }), Err(Errno::Einval));
}

/// The destination must belong to the userfaultfd issuing the move, by
/// IDENTITY. "Some monitor registered it" is not enough: a move publishes
/// pages at an address someone else is responsible for.
#[test]
fn move_requires_the_destination_to_belong_to_this_context() {
    let (s, d) = (movable(), movable());
    assert_eq!(check_move_areas(&s, &MoveVma { registered_by_this_ctx: false, ..d }),
               Err(Errno::Einval));
    // The SOURCE needs no registration — it is memory being taken away, not
    // memory being published.
    assert_eq!(check_move_areas(&MoveVma { registered_by_this_ctx: false, ..s }, &d), Ok(()));
}
