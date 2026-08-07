// pkey syscall errno conformance, both arch descriptors, hosted.
//
// Every expectation is traced from Linux source. `pkey_alloc(2)` documents
// only ENOSPC and is silent about x86's first-call EINVAL; B1434 believed the
// man page's shape and shipped ENOSPC on both arches.

use super::*;

fn fresh(a: &PkeyAbi) -> u16 { a.mm.init_map }

#[test]
fn flags_are_rejected_before_init_val() {
    for a in [&X86_64, &AARCH64] {
        let mut m = fresh(a);
        // Wrong in BOTH ways: Linux still reports the flags error, and never
        // reaches the allocator, so the map is untouched.
        assert_eq!(pkey_alloc(a, &mut m, 1, !0), Err(Errno::Einval));
        assert_eq!(pkey_alloc(a, &mut m, 0x8000, 0), Err(Errno::Einval));
        assert_eq!(m, fresh(a));
    }
}

#[test]
fn access_mask_differs_between_the_arches() {
    assert_eq!(X86_64.access_mask, 0x3);
    assert_eq!(AARCH64.access_mask, 0xF);
    // PKEY_DISABLE_READ / _EXECUTE exist only on arm64: x86 rejects them as
    // out-of-mask init_val, arm64 accepts them and fails later at the allocator.
    let mut x = fresh(&X86_64);
    assert_eq!(pkey_alloc(&X86_64, &mut x, 0, PKEY_DISABLE_READ), Err(Errno::Einval));
    assert_eq!(pkey_alloc(&X86_64, &mut x, 0, PKEY_DISABLE_EXECUTE), Err(Errno::Einval));
    assert_eq!(x, fresh(&X86_64), "rejected init_val must not consume a key");
    let mut r = fresh(&AARCH64);
    assert_eq!(pkey_alloc(&AARCH64, &mut r, 0, PKEY_DISABLE_READ), Err(Errno::Enospc));
    assert_eq!(pkey_alloc(&AARCH64, &mut r, 0, PKEY_DISABLE_EXECUTE), Err(Errno::Enospc));
    // Bits above either mask are EINVAL everywhere.
    for a in [&X86_64, &AARCH64] {
        let mut m = fresh(a);
        assert_eq!(pkey_alloc(a, &mut m, 0, 0x10), Err(Errno::Einval));
        assert_eq!(pkey_alloc(a, &mut m, 0, !a.access_mask), Err(Errno::Einval));
    }
}

#[test]
fn x86_first_alloc_is_einval_then_enospc_forever() {
    // THE B1434 correction. x86's `mm_pkey_alloc` has no `arch_pkeys_enabled`
    // guard and the map starts empty without OSPKE, so call 1 gets a key and
    // dies in `arch_set_user_pkey_access` with EINVAL; the failed rollback
    // leaves the map full, so call 2 onward is ENOSPC.
    let mut m = fresh(&X86_64);
    assert_eq!(pkey_alloc(&X86_64, &mut m, 0, 0), Err(Errno::Einval));
    for _ in 0..4 { assert_eq!(pkey_alloc(&X86_64, &mut m, 0, 0), Err(Errno::Enospc)); }
    // Same for every legal init_val — the errno does not depend on it.
    for iv in [0, PKEY_DISABLE_ACCESS, PKEY_DISABLE_WRITE, X86_64.access_mask] {
        let mut m = fresh(&X86_64);
        assert_eq!(pkey_alloc(&X86_64, &mut m, 0, iv), Err(Errno::Einval));
        assert_eq!(pkey_alloc(&X86_64, &mut m, 0, iv), Err(Errno::Enospc));
    }
}

#[test]
fn arm64_alloc_is_enospc_from_the_very_first_call() {
    for iv in [0, PKEY_DISABLE_ACCESS, PKEY_DISABLE_WRITE, PKEY_DISABLE_READ, AARCH64.access_mask] {
        let mut m = fresh(&AARCH64);
        for _ in 0..4 { assert_eq!(pkey_alloc(&AARCH64, &mut m, 0, iv), Err(Errno::Enospc)); }
        assert_eq!(m, fresh(&AARCH64));
    }
}

#[test]
fn pkey_free_of_the_default_key_differs_between_the_arches() {
    // arm64 reserves key 0 in every mm, so freeing it succeeds once.
    let mut r = fresh(&AARCH64);
    assert_eq!(pkey_free(&AARCH64, &mut r, 0), Ok(()));
    assert_eq!(pkey_free(&AARCH64, &mut r, 0), Err(Errno::Einval));
    // x86 without OSPKE never has key 0 allocated (it reads as the
    // execute-only key), so freeing it is EINVAL from the start.
    let mut x = fresh(&X86_64);
    assert_eq!(pkey_free(&X86_64, &mut x, 0), Err(Errno::Einval));
}

#[test]
fn pkey_free_rejects_out_of_range_keys_on_both_arches() {
    for a in [&X86_64, &AARCH64] {
        let mut m = fresh(a);
        for k in [-1, -2, i32::MIN, a.mm.max_pkey, 16, i32::MAX] {
            assert_eq!(pkey_free(a, &mut m, k), Err(Errno::Einval), "key {k}");
        }
    }
}

#[test]
fn pkey_mprotect_keep_always_allowed_default_key_only_on_arm64() {
    for a in [&X86_64, &AARCH64] { assert!(pkey_mprotect_allows(a, fresh(a), PKEY_KEEP)); }
    assert!(pkey_mprotect_allows(&AARCH64, fresh(&AARCH64), 0));
    assert!(!pkey_mprotect_allows(&X86_64, fresh(&X86_64), 0));
    for a in [&X86_64, &AARCH64] {
        for k in [1, 2, 15, 16, i32::MAX, -2, i32::MIN] {
            assert!(!pkey_mprotect_allows(a, fresh(a), k), "key {k} must be EINVAL");
        }
    }
}

#[test]
fn arm64_mprotect_follows_the_map_after_a_free() {
    let mut m = fresh(&AARCH64);
    assert!(pkey_mprotect_allows(&AARCH64, m, 0));
    assert_eq!(pkey_free(&AARCH64, &mut m, 0), Ok(()));
    assert!(!pkey_mprotect_allows(&AARCH64, m, 0), "freed key is no longer usable");
    assert!(pkey_mprotect_allows(&AARCH64, m, PKEY_KEEP));
}

#[test]
fn x86_map_after_the_failed_alloc_still_refuses_key_zero_for_mprotect() {
    // The leaked bit makes alloc report ENOSPC, but `mm_pkey_is_allocated`
    // still excludes key 0 (execute-only), so pkey_mprotect stays EINVAL.
    let mut m = fresh(&X86_64);
    assert_eq!(pkey_alloc(&X86_64, &mut m, 0, 0), Err(Errno::Einval));
    assert_eq!(m, 0x1);
    assert!(!pkey_mprotect_allows(&X86_64, m, 0));
    assert_eq!(pkey_free(&X86_64, &mut m, 0), Err(Errno::Einval));
}

#[test]
fn enabled_hardware_allocates_a_real_key_without_rollback() {
    let x86 = with_mm(X86_64, pkeys::PkeyArch {
        max_pkey: 16, init_map: 1, alloc_checks_hw: false, execute_only_pkey: Some(-1),
    });
    let mut map = x86.mm.init_map;
    assert_eq!(pkey_alloc(&x86, &mut map, 0, PKEY_DISABLE_WRITE), Ok(1));
    assert!(pkey_mprotect_allows(&x86, map, 1));

    let arm = with_mm(AARCH64, pkeys::PkeyArch {
        max_pkey: 8, init_map: 1, alloc_checks_hw: false, execute_only_pkey: None,
    });
    let mut map = arm.mm.init_map;
    assert_eq!(pkey_alloc(&arm, &mut map, 0, PKEY_DISABLE_READ), Ok(1));
    assert!(pkey_mprotect_allows(&arm, map, 1));
}
