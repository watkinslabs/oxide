// Creation, handshake, ordering and range ladders.
// Every assertion here is a REFUSAL: the value of this module is that the
// unregistered fill and the unprivileged create fail.

use crate::userfaultfd::policy::*;
use crate::userfaultfd::uapi::*;
use syscall::errno::Errno;

const PAGE: u64 = hal::PAGE_SIZE_BYTES;

// ---- creation gate --------------------------------------------------------

#[test]
fn unprivileged_kernel_fault_context_is_denied_with_eperm() {
    assert_eq!(check_create(0, false, false), Err(Errno::Eperm));
    assert_eq!(check_create(O_CLOEXEC, false, false), Err(Errno::Eperm));
}

#[test]
fn user_mode_only_is_always_allowed() {
    assert_eq!(check_create(UFFD_USER_MODE_ONLY, false, false), Ok(()));
}

#[test]
fn cap_sys_ptrace_or_sysctl_opens_the_kernel_fault_context() {
    assert_eq!(check_create(0, true, false), Ok(()));
    assert_eq!(check_create(0, false, true), Ok(()));
}

#[test]
fn eperm_gate_precedes_the_unknown_flag_check() {
    let garbage = 1 << 20;
    assert_eq!(check_create(garbage, false, false), Err(Errno::Eperm));
    assert_eq!(check_create(garbage, true, false), Err(Errno::Einval));
}

#[test]
fn every_documented_flag_combination_is_accepted() {
    assert_eq!(check_create(UFFD_ALL_FLAGS, true, false), Ok(()));
}

// ---- range validation -----------------------------------------------------

#[test]
fn range_validation_matches_the_einval_ladder() {
    assert_eq!(validate_range(PAGE, PAGE), Ok(()));
    assert_eq!(validate_range(PAGE, 1), Err(Errno::Einval));
    assert_eq!(validate_range(PAGE, 0), Err(Errno::Einval));
    assert_eq!(validate_range(PAGE + 1, PAGE), Err(Errno::Einval));
    assert_eq!(validate_unaligned_range(PAGE + 1, PAGE), Ok(()));
    assert_eq!(validate_range(hal::USER_VA_END, PAGE), Err(Errno::Einval));
    assert_eq!(validate_range(hal::USER_VA_END - PAGE, 2 * PAGE), Err(Errno::Einval));
    assert_eq!(validate_range(u64::MAX & !(PAGE - 1), PAGE), Err(Errno::Einval));
}

// ---- UFFDIO_API -----------------------------------------------------------

#[test]
fn api_reports_a_nonzero_ioctls_bitmap() {
    let r = api_negotiate(UFFD_API, 0, false, 0).expect("handshake");
    assert_eq!(r.ioctls, UFFD_API_IOCTLS);
    assert_eq!(r.ioctls, (1 << 0) | (1 << 1) | (1u64 << 0x3F));
    assert!(is_initialized(r.ctx_features));
}

#[test]
fn api_rejects_a_foreign_api_number() {
    assert!(matches!(api_negotiate(0xAB, 0, false, 0), Err(Errno::Einval)));
}

/// Advertising a feature is a promise. Each bit named here is either wired to
/// behaviour a monitor can observe, or refused — never accepted and ignored.
#[test]
fn api_offers_exactly_the_features_that_are_wired() {
    // The fork-event capability check runs BEFORE the "do we implement it"
    // rejection, so an unprivileged request for it reports EPERM.
    assert_eq!(api_negotiate(UFFD_API, feature::EVENT_FORK, false, 0).err(), Some(Errno::Eperm));
    assert_eq!(api_negotiate(UFFD_API, feature::EVENT_FORK, true, 0).err(), Some(Errno::Einval));
    for unwired in [feature::SIGBUS, feature::EVENT_REMAP, feature::EXACT_ADDRESS,
                    feature::MISSING_HUGETLBFS, feature::MINOR_HUGETLBFS,
                    feature::WP_UNPOPULATED, feature::WP_ASYNC, feature::WP_HUGETLBFS_SHMEM] {
        assert_eq!(api_negotiate(UFFD_API, unwired, true, 0).err(), Some(Errno::Einval),
                   "unwired feature {unwired:#x} must be refused, not accepted and ignored");
    }
    for wired in [feature::THREAD_ID, feature::PAGEFAULT_FLAG_WP, feature::MISSING_SHMEM,
                  feature::MINOR_SHMEM, feature::POISON, feature::MOVE] {
        assert!(api_negotiate(UFFD_API, wired, true, 0).is_ok(),
                "wired feature {wired:#x} must be offered");
    }
    let all = api_negotiate(UFFD_API, 0, false, 0).expect("handshake").features;
    assert_eq!(all, UFFD_API_FEATURES);
}

#[test]
fn a_second_handshake_is_refused() {
    let first = api_negotiate(UFFD_API, 0, false, 0).expect("handshake");
    assert_eq!(api_negotiate(UFFD_API, 0, false, first.ctx_features).err(), Some(Errno::Einval));
}

#[test]
fn every_op_except_api_needs_the_handshake_first() {
    for op in [UFFDIO_COPY, UFFDIO_REGISTER, UFFDIO_WRITEPROTECT, UFFDIO_CONTINUE,
               UFFDIO_POISON, UFFDIO_MOVE] {
        assert_eq!(check_ioctl_ordering(op, 0), Err(Errno::Einval));
        assert_eq!(check_ioctl_ordering(op, feature::INITIALIZED), Ok(()));
    }
    assert_eq!(check_ioctl_ordering(UFFDIO_API, 0), Ok(()));
}

// ---- user-mode-only -------------------------------------------------------

#[test]
fn user_mode_only_context_refuses_kernel_mode_faults() {
    assert!(may_deliver_fault(UFFD_USER_MODE_ONLY, true));
    assert!(!may_deliver_fault(UFFD_USER_MODE_ONLY, false),
        "a user-mode-only uffd must not park the kernel inside a uaccess");
    assert!(may_deliver_fault(0, true));
    assert!(may_deliver_fault(0, false));
}

// ---- ABI sizes ------------------------------------------------------------

#[test]
fn struct_sizes_match_the_ioctl_request_encodings() {
    // The size field is bits 16..30 of the request number.
    let size_of_req = |r: u64| (r >> 16) & 0x3FFF;
    assert_eq!(size_of_req(UFFDIO_API), UFFDIO_API_SIZE);
    assert_eq!(size_of_req(UFFDIO_REGISTER), UFFDIO_REGISTER_SIZE);
    assert_eq!(size_of_req(UFFDIO_UNREGISTER), UFFDIO_RANGE_SIZE);
    assert_eq!(size_of_req(UFFDIO_WAKE), UFFDIO_RANGE_SIZE);
    assert_eq!(size_of_req(UFFDIO_COPY), UFFDIO_COPY_SIZE);
    assert_eq!(size_of_req(UFFDIO_ZEROPAGE), UFFDIO_ZEROPAGE_SIZE);
    assert_eq!(size_of_req(UFFDIO_MOVE), UFFDIO_MOVE_SIZE);
    assert_eq!(size_of_req(UFFDIO_WRITEPROTECT), UFFDIO_WRITEPROTECT_SIZE);
    assert_eq!(size_of_req(UFFDIO_CONTINUE), UFFDIO_CONTINUE_SIZE);
    assert_eq!(size_of_req(UFFDIO_POISON), UFFDIO_POISON_SIZE);
    // Every reply word sits in the last u64 of its object.
    assert_eq!(UFFDIO_REGISTER_IOCTLS_OFF, UFFDIO_REGISTER_SIZE - 8);
    assert_eq!(UFFDIO_COPY_COPY_OFF, UFFDIO_COPY_SIZE - 8);
    assert_eq!(UFFDIO_ZEROPAGE_ZEROPAGE_OFF, UFFDIO_ZEROPAGE_SIZE - 8);
    assert_eq!(UFFDIO_MOVE_MOVE_OFF, UFFDIO_MOVE_SIZE - 8);
    assert_eq!(UFFDIO_CONTINUE_MAPPED_OFF, UFFDIO_CONTINUE_SIZE - 8);
    assert_eq!(UFFDIO_POISON_UPDATED_OFF, UFFDIO_POISON_SIZE - 8);
    // The write-protect object has no reply word at all: 24 bytes is exactly a
    // range plus a mode.
    assert_eq!(UFFDIO_WRITEPROTECT_SIZE, UFFDIO_RANGE_SIZE + 8);
}

/// A command number decodes to exactly one slot, and the slot numbers are what
/// the reply bitmaps are built from. A collision here would make a monitor
/// issue one command believing it had been promised another.
#[test]
fn every_command_number_carries_its_own_slot() {
    let nr = |r: u64| ((r >> 8) & 0xFF, r & 0xFF);
    for (req, s) in [(UFFDIO_REGISTER, slot::REGISTER), (UFFDIO_UNREGISTER, slot::UNREGISTER),
                     (UFFDIO_WAKE, slot::WAKE), (UFFDIO_COPY, slot::COPY),
                     (UFFDIO_ZEROPAGE, slot::ZEROPAGE), (UFFDIO_MOVE, slot::MOVE),
                     (UFFDIO_WRITEPROTECT, slot::WRITEPROTECT),
                     (UFFDIO_CONTINUE, slot::CONTINUE), (UFFDIO_POISON, slot::POISON),
                     (UFFDIO_API, slot::API)] {
        let (kind, cmd) = nr(req);
        assert_eq!(kind, 0xAA, "request {req:#x} is not a userfaultfd command");
        assert_eq!(cmd, s as u64, "request {req:#x} decodes to the wrong slot");
    }
}
