// Protection-key allocation conformance, both arch descriptors, on whichever
// host runs the hosted suite. Every expectation below is traced from the
// verified kernel behaviour, not from the man page: `pkey_alloc(2)` documents
// only ENOSPC and is silent about the x86 first-call EINVAL that falls out
// of the per-arch user-pkey-access setup.

use super::*;

/// The mm state a fresh mm of that arch starts with.
fn st(a: &PkeyArch) -> PkeyState { PkeyState::new(a) }

#[test]
fn masks_and_shapes_match_each_arch() {
    assert_eq!(X86_64.all_pkeys_mask(), 0x1);   // (1 << 1) - 1
    assert_eq!(AARCH64.all_pkeys_mask(), 0xFF); // GENMASK(7, 0)
}

#[test]
fn x86_leaves_the_map_empty_without_ospke() {
    // `init_new_context` writes 0x1 only under `cpu_feature_enabled(OSPKE)`.
    assert_eq!(X86_64.init_map, 0);
    // ... and `execute_only_pkey` is likewise left at 0, so key 0 — the key a
    // reader would assume is "the implicit default" — is not allocated.
    assert!(!mm_pkey_is_allocated(&X86_64, &st(&X86_64), 0));
}

#[test]
fn arm64_reserves_key_zero_unconditionally() {
    assert_eq!(AARCH64.init_map, 1);
    assert!(mm_pkey_is_allocated(&AARCH64, &st(&AARCH64), 0));
}

#[test]
fn x86_first_alloc_succeeds_in_the_mm_then_the_map_stays_dirty() {
    // The x86 `mm_pkey_alloc` has no `arch_pkeys_enabled()` guard, so with an
    // empty map it hands out key 0 even though the hardware cannot enforce it.
    let mut s = st(&X86_64);
    assert_eq!(mm_pkey_alloc(&X86_64, &mut s), 0);
    assert_eq!(s.map, 0x1);
    // `pkey_alloc`'s rollback then fails, because key 0 == execute_only_pkey.
    assert!(!mm_pkey_free(&X86_64, &mut s, 0));
    assert_eq!(s.map, 0x1, "failed mm_pkey_free must not clear the bit");
    // Which is why the SECOND allocation finds the map full.
    assert_eq!(mm_pkey_alloc(&X86_64, &mut s), PKEY_ALLOC_FAILED);
}

#[test]
fn arm64_alloc_fails_immediately_without_poe() {
    let mut s = st(&AARCH64);
    for _ in 0..4 {
        assert_eq!(mm_pkey_alloc(&AARCH64, &mut s), PKEY_ALLOC_FAILED);
        assert_eq!(s.map, AARCH64.init_map, "guarded alloc must not touch the map");
    }
}

#[test]
fn arm64_can_free_the_default_key_but_x86_cannot() {
    let mut arm = st(&AARCH64);
    assert!(mm_pkey_free(&AARCH64, &mut arm, 0));
    assert_eq!(arm.map, 0);
    assert!(!mm_pkey_free(&AARCH64, &mut arm, 0), "second free is EINVAL");

    let mut x86 = st(&X86_64);
    assert!(!mm_pkey_free(&X86_64, &mut x86, 0));
}

#[test]
fn out_of_range_and_negative_keys_are_never_allocated() {
    for a in [&X86_64, &AARCH64] {
        for k in [-1, -2, i32::MIN, a.max_pkey, a.max_pkey + 1, 16, i32::MAX] {
            let full = PkeyState { map: 0xFFFF, execute_only: EXEC_ONLY_UNSET };
            assert!(!mm_pkey_is_allocated(a, &full, k), "key {k} out of range for max {}", a.max_pkey);
        }
    }
}

#[test]
fn arm64_walks_keys_in_order_when_the_hardware_gate_is_lifted() {
    // Same descriptor with the guard removed models a POE-capable CPU: ffz
    // must hand out 1,2,3,... above the reserved key 0, then run out at 8.
    let poe = PkeyArch { alloc_checks_hw: false, ..AARCH64 };
    let mut s = st(&poe);
    for expect in 1..8 { assert_eq!(mm_pkey_alloc(&poe, &mut s), expect); }
    assert_eq!(s.map, 0xFF);
    assert_eq!(mm_pkey_alloc(&poe, &mut s), PKEY_ALLOC_FAILED);
    assert!(mm_pkey_free(&poe, &mut s, 3));
    assert_eq!(mm_pkey_alloc(&poe, &mut s), 3, "ffz reuses the freed slot");
}

#[test]
fn context_forks_the_map_verbatim() {
    let parent = PkeyContext::new();
    parent.with_state(|s| { s.map = 0x25; s.execute_only = 3; });
    let child = PkeyContext::forked(&parent);
    assert_eq!(child.with_state(|s| (s.map, s.execute_only)), (0x25, 3));
    // ... and is thereafter independent (`dup_mm` copies, it does not share).
    child.with_state(|s| { s.map = 0; s.execute_only = EXEC_ONLY_UNSET; });
    assert_eq!(parent.with_state(|s| (s.map, s.execute_only)), (0x25, 3));
}

#[test]
fn fresh_context_uses_this_arch_initial_map() {
    assert_eq!(PkeyContext::new().with_state(|s| s.map), ARCH.init_map);
}

#[test]
fn the_hardware_predicate_agrees_with_each_arch_own_test() {
    // Neither arch's descriptor alone answers this: one keeps its key count
    // at 8 with the feature off, the other collapses it to 1 and has no
    // guard in its allocator.
    assert!(!X86_64.pkeys_enabled());
    assert!(!AARCH64.pkeys_enabled());
    assert!(PkeyArch { max_pkey: 16, ..X86_64 }.pkeys_enabled());
    assert!(PkeyArch { alloc_checks_hw: false, ..AARCH64 }.pkeys_enabled());
    // The feature-off arm64 runtime shape: guarded AND collapsed.
    assert!(!PkeyArch { max_pkey: 1, ..AARCH64 }.pkeys_enabled());
}

#[test]
fn a_fresh_context_starts_with_no_execute_only_key_dedicated() {
    assert_eq!(PkeyContext::new().with_state(|s| s.execute_only),
               ARCH.execute_only_init.unwrap_or(EXEC_ONLY_UNSET));
}
