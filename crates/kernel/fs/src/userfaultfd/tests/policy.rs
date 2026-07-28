// `policy.rs` ladders vs Linux `mm/userfaultfd.c` (v7.2.0-rc4).
// Every assertion here is a REFUSAL: the value of this module is that the
// unregistered copy, the unprivileged create and the silently-accepted WP
// registration all fail.

use crate::userfaultfd::policy::*;
use crate::userfaultfd::uapi::*;
use syscall::errno::Errno;

const PAGE: u64 = hal::PAGE_SIZE_BYTES;

// ---- userfaultfd_syscall_allowed -----------------------------------------

#[test]
fn unprivileged_kernel_fault_context_is_denied_with_eperm() {
    // No UFFD_USER_MODE_ONLY, no CAP_SYS_PTRACE, sysctl off → EPERM.
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
    // Linux runs userfaultfd_syscall_allowed in SYSCALL_DEFINE1 BEFORE
    // new_userfaultfd rejects unknown bits, so garbage flags from an
    // unprivileged caller report EPERM, not EINVAL.
    let garbage = 1 << 20;
    assert_eq!(check_create(garbage, false, false), Err(Errno::Eperm));
    assert_eq!(check_create(garbage, true, false), Err(Errno::Einval));
}

#[test]
fn every_documented_flag_combination_is_accepted() {
    assert_eq!(check_create(UFFD_ALL_FLAGS, true, false), Ok(()));
}

// ---- validate_range / validate_unaligned_range ----------------------------

#[test]
fn range_validation_matches_linux_einval_ladder() {
    assert_eq!(validate_range(PAGE, PAGE), Ok(()));
    // len not a page multiple
    assert_eq!(validate_range(PAGE, 1), Err(Errno::Einval));
    // zero length
    assert_eq!(validate_range(PAGE, 0), Err(Errno::Einval));
    // unaligned start (validate_range only; the unaligned variant allows it)
    assert_eq!(validate_range(PAGE + 1, PAGE), Err(Errno::Einval));
    assert_eq!(validate_unaligned_range(PAGE + 1, PAGE), Ok(()));
    // start at/above task_size
    assert_eq!(validate_range(hal::USER_VA_END, PAGE), Err(Errno::Einval));
    // range runs past task_size
    assert_eq!(validate_range(hal::USER_VA_END - PAGE, 2 * PAGE), Err(Errno::Einval));
    // wrap
    assert_eq!(validate_range(u64::MAX & !(PAGE - 1), PAGE), Err(Errno::Einval));
}

// ---- UFFDIO_API -----------------------------------------------------------

#[test]
fn api_reports_a_nonzero_ioctls_bitmap() {
    // The old struct was 16 bytes and never wrote `ioctls`; a monitor probing
    // for UFFDIO_REGISTER support read whatever it had left there.
    let r = api_negotiate(UFFD_API, 0, false, 0).expect("handshake");
    assert_eq!(r.ioctls, UFFD_API_IOCTLS);
    assert_ne!(r.ioctls, 0);
    // UFFD_API_IOCTLS is REGISTER|UNREGISTER|API — bits 0, 1 and 0x3F.
    assert_eq!(r.ioctls, (1 << 0) | (1 << 1) | (1u64 << 0x3F));
    assert!(is_initialized(r.ctx_features));
}

#[test]
fn api_rejects_a_foreign_api_number() {
    assert!(matches!(api_negotiate(0xAB, 0, false, 0), Err(Errno::Einval)));
}

#[test]
fn api_rejects_unsupported_features_instead_of_silently_zeroing_them() {
    // EVENT_FORK additionally needs CAP_SYS_PTRACE, and that EPERM is checked
    // before the "do we implement it" EINVAL.
    assert_eq!(api_negotiate(UFFD_API, feature::EVENT_FORK, false, 0).err(), Some(Errno::Eperm));
    assert_eq!(api_negotiate(UFFD_API, feature::EVENT_FORK, true, 0).err(), Some(Errno::Einval));
    assert_eq!(api_negotiate(UFFD_API, feature::SIGBUS, false, 0).err(), Some(Errno::Einval));
    assert_eq!(api_negotiate(UFFD_API, feature::MOVE, false, 0).err(), Some(Errno::Einval));
    // THREAD_ID is the one feature actually wired.
    assert!(api_negotiate(UFFD_API, feature::THREAD_ID, false, 0).is_ok());
}

#[test]
fn a_second_handshake_is_refused() {
    let first = api_negotiate(UFFD_API, 0, false, 0).expect("handshake");
    assert_eq!(api_negotiate(UFFD_API, 0, false, first.ctx_features).err(), Some(Errno::Einval));
}

#[test]
fn every_op_except_api_needs_the_handshake_first() {
    assert_eq!(check_ioctl_ordering(UFFDIO_COPY, 0), Err(Errno::Einval));
    assert_eq!(check_ioctl_ordering(UFFDIO_REGISTER, 0), Err(Errno::Einval));
    assert_eq!(check_ioctl_ordering(UFFDIO_API, 0), Ok(()));
    assert_eq!(check_ioctl_ordering(UFFDIO_COPY, feature::INITIALIZED), Ok(()));
}

// ---- UFFDIO_REGISTER ------------------------------------------------------

#[test]
fn register_refuses_wp_and_minor_rather_than_accepting_a_no_op() {
    assert_eq!(check_register_mode(UFFDIO_REGISTER_MODE_MISSING), Ok(()));
    assert_eq!(check_register_mode(UFFDIO_REGISTER_MODE_WP), Err(Errno::Einval));
    assert_eq!(check_register_mode(UFFDIO_REGISTER_MODE_MINOR), Err(Errno::Einval));
    assert_eq!(check_register_mode(UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_WP),
               Err(Errno::Einval));
    assert_eq!(check_register_mode(0), Err(Errno::Einval));
    assert_eq!(check_register_mode(1 << 9), Err(Errno::Einval));
}

#[test]
fn range_ioctls_bitmap_uses_linux_slot_numbers() {
    let m = register_ioctls(UFFDIO_REGISTER_MODE_MISSING);
    // Linux: _UFFDIO_WAKE=2, _UFFDIO_COPY=3, _UFFDIO_ZEROPAGE=4. The old code
    // reported bits 1|2|3, which advertises UNREGISTER and hides ZEROPAGE.
    assert_eq!(m, (1 << 2) | (1 << 3) | (1 << 4));
    assert_eq!(m & (1 << slot::UNREGISTER), 0);
    assert_ne!(m & (1 << slot::ZEROPAGE), 0);
    // Never promise an op this kernel does not implement.
    for s in [slot::MOVE, slot::WRITEPROTECT, slot::CONTINUE, slot::POISON] {
        assert_eq!(m & (1 << s), 0, "advertised unimplemented slot {s}");
    }
}

#[test]
fn register_vma_scan_enforces_maywrite_and_single_owner() {
    let ok = RegVma { can_userfault: true, may_write: true, owned_by_other_uffd: false };
    assert_eq!(check_register_vma(&ok), Ok(()));
    assert_eq!(check_register_vma(&RegVma { can_userfault: false, ..ok }), Err(Errno::Einval));
    assert_eq!(check_register_vma(&RegVma { may_write: false, ..ok }), Err(Errno::Eperm));
    assert_eq!(check_register_vma(&RegVma { owned_by_other_uffd: true, ..ok }), Err(Errno::Ebusy));
    // Order: a non-userfaultable VMA reports EINVAL even without VM_MAYWRITE.
    assert_eq!(check_register_vma(&RegVma { can_userfault: false, may_write: false, ..ok }),
               Err(Errno::Einval));
}

// ---- UFFDIO_COPY / UFFDIO_ZEROPAGE destination ----------------------------

#[test]
fn copy_into_an_unmapped_destination_is_refused() {
    assert_eq!(check_dst_vma(PAGE, None, false), Err(Errno::Enoent));
}

#[test]
fn copy_into_an_unregistered_vma_is_refused() {
    let v = DstVma { end: 16 * PAGE, uffd_registered: false, uffd_wp: false };
    assert_eq!(check_dst_vma(PAGE, Some(v), false), Err(Errno::Enoent));
}

#[test]
fn copy_running_past_the_vma_end_is_refused() {
    let v = DstVma { end: 4 * PAGE, uffd_registered: true, uffd_wp: false };
    assert_eq!(check_dst_vma(4 * PAGE, Some(v), false), Ok(()));
    assert_eq!(check_dst_vma(4 * PAGE + 1, Some(v), false), Err(Errno::Enoent));
}

#[test]
fn mode_wp_copy_reports_enoent_before_einval_at_an_unmapped_address() {
    // Linux checks MFILL_ATOMIC_WP against the VMA inside mfill_get_vma, i.e.
    // AFTER the lookup, so the missing destination wins.
    assert_eq!(check_dst_vma(PAGE, None, true), Err(Errno::Enoent));
    let v = DstVma { end: 16 * PAGE, uffd_registered: true, uffd_wp: false };
    assert_eq!(check_dst_vma(PAGE, Some(v), true), Err(Errno::Einval));
}

#[test]
fn fill_mode_bits_follow_linux() {
    assert_eq!(check_copy_mode(0), Ok(()));
    assert_eq!(check_copy_mode(UFFDIO_COPY_MODE_DONTWAKE), Ok(()));
    assert_eq!(check_copy_mode(UFFDIO_COPY_MODE_WP), Ok(()));
    assert_eq!(check_copy_mode(1 << 5), Err(Errno::Einval));
    assert_eq!(check_zeropage_mode(UFFDIO_ZEROPAGE_MODE_DONTWAKE), Ok(()));
    assert_eq!(check_zeropage_mode(UFFDIO_COPY_MODE_WP), Err(Errno::Einval));
}

#[test]
fn short_fill_reports_eagain_not_enomem() {
    // Linux: `ret = range.len == uffdio_copy.len ? 0 : -EAGAIN`.
    assert_eq!(fill_retval(2 * PAGE, 2 * PAGE, None), (0, 2 * PAGE as i64));
    let (rv, count) = fill_retval(PAGE, 2 * PAGE, Some(Errno::Enomem));
    assert_eq!(rv, -(Errno::Eagain.as_i32() as i64));
    assert_eq!(count, PAGE as i64);
    // Nothing installed → the field carries the negative errno and the ioctl
    // returns it (mfill_atomic's `copied ? copied : err`).
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

// ---- UFFD_USER_MODE_ONLY --------------------------------------------------

#[test]
fn user_mode_only_context_refuses_kernel_mode_faults() {
    assert!(may_deliver_fault(UFFD_USER_MODE_ONLY, true));
    assert!(!may_deliver_fault(UFFD_USER_MODE_ONLY, false),
        "a USER_MODE_ONLY uffd must not park the kernel inside a uaccess");
    // A privileged context without the flag handles both.
    assert!(may_deliver_fault(0, true));
    assert!(may_deliver_fault(0, false));
}

// ---- ABI sizes ------------------------------------------------------------

#[test]
fn struct_sizes_match_the_ioctl_request_encodings() {
    // _IOC size field is bits 16..30 of the request number.
    let size_of_req = |r: u64| (r >> 16) & 0x3FFF;
    assert_eq!(size_of_req(UFFDIO_API), UFFDIO_API_SIZE);
    assert_eq!(size_of_req(UFFDIO_REGISTER), UFFDIO_REGISTER_SIZE);
    assert_eq!(size_of_req(UFFDIO_UNREGISTER), UFFDIO_RANGE_SIZE);
    assert_eq!(size_of_req(UFFDIO_WAKE), UFFDIO_RANGE_SIZE);
    assert_eq!(size_of_req(UFFDIO_COPY), UFFDIO_COPY_SIZE);
    assert_eq!(size_of_req(UFFDIO_ZEROPAGE), UFFDIO_ZEROPAGE_SIZE);
    // The reply words sit in the last u64 of each object.
    assert_eq!(UFFDIO_REGISTER_IOCTLS_OFF, UFFDIO_REGISTER_SIZE - 8);
    assert_eq!(UFFDIO_COPY_COPY_OFF, UFFDIO_COPY_SIZE - 8);
    assert_eq!(UFFDIO_ZEROPAGE_ZEROPAGE_OFF, UFFDIO_ZEROPAGE_SIZE - 8);
}
