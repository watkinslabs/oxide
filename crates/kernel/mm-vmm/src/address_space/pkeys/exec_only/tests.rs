// Execute-only protection key + plain-mprotect key override.
//
// The expectations encode verified kernel behaviour, including the two that
// read as surprises: the register write is SKIPPED for an already-armed key,
// and a failed arming releases the bit directly because the ordinary free
// refuses to touch the execute-only key.

use super::*;
use crate::address_space::pkeys::{AARCH64, PkeyArch, PkeyState, X86_64, mm_pkey_is_allocated};

/// A rights register that records every call and can be made to fail.
struct Rights { denied: alloc::vec::Vec<i32>, reads_allowed: bool, deny_ok: bool }
impl Rights {
    fn new() -> Self { Self { denied: alloc::vec::Vec::new(), reads_allowed: true, deny_ok: true } }
}
impl ExecOnlyRights for Rights {
    fn allows_read(&self, _pkey: i32) -> bool { self.reads_allowed }
    fn deny_access(&mut self, pkey: i32) -> bool { self.denied.push(pkey); self.deny_ok }
}

fn x86_ospke() -> PkeyArch { PkeyArch { max_pkey: 16, init_map: 1, execute_only_init: Some(EXEC_ONLY_UNSET), ..X86_64 } }
fn arm_poe() -> PkeyArch { PkeyArch { alloc_checks_hw: false, ..AARCH64 } }

fn keep() -> i32 { PKEY_KEEP }

#[test]
fn the_first_execute_only_mapping_allocates_and_arms_one_key() {
    let a = x86_ospke();
    let mut st = PkeyState::new(&a);
    let mut r = Rights::new();
    let k = execute_only_pkey(&a, &mut st, &mut r);
    assert!(k > 0, "key 0 is the default key and can never be the execute-only one here");
    assert_eq!(st.execute_only, k, "the key must be stored back in the mm");
    assert_eq!(r.denied, alloc::vec![k], "the key must be denied in the register exactly once");
    // ... and a second execute-only mapping reuses it without re-arming.
    r.reads_allowed = false;
    assert_eq!(execute_only_pkey(&a, &mut st, &mut r), k);
    assert_eq!(r.denied, alloc::vec![k], "an already-armed key must not be re-written");
}

#[test]
fn a_dedicated_key_whose_reads_were_reopened_is_re_armed() {
    let a = x86_ospke();
    let mut st = PkeyState::new(&a);
    let mut r = Rights::new();
    let k = execute_only_pkey(&a, &mut st, &mut r);
    // The program reopened reads through the key itself.
    r.reads_allowed = true;
    assert_eq!(execute_only_pkey(&a, &mut st, &mut r), k);
    assert_eq!(r.denied, alloc::vec![k, k]);
}

#[test]
fn the_execute_only_key_is_invisible_to_every_user_interface() {
    let a = x86_ospke();
    let mut st = PkeyState::new(&a);
    let mut r = Rights::new();
    let k = execute_only_pkey(&a, &mut st, &mut r);
    assert!(st.map & (1u16 << k) != 0, "the bit is set, so nothing else can be handed the key");
    assert!(!mm_pkey_is_allocated(&a, &st, k), "yet the key must not be free-able or mprotect-able");
}

#[test]
fn a_register_that_cannot_be_armed_releases_the_key_it_took() {
    let a = x86_ospke();
    let mut st = PkeyState::new(&a);
    let before = st.map;
    let mut r = Rights::new();
    r.deny_ok = false;
    assert_eq!(execute_only_pkey(&a, &mut st, &mut r), PKEY_ALLOC_FAILED);
    assert_eq!(st.map, before, "a failed arming must not leak the allocation bit");
    assert_eq!(st.execute_only, EXEC_ONLY_UNSET, "and must not record the key");
}

#[test]
fn an_exhausted_allocation_map_yields_no_execute_only_key() {
    let a = x86_ospke();
    let mut st = PkeyState { map: a.all_pkeys_mask(), execute_only: EXEC_ONLY_UNSET };
    let mut r = Rights::new();
    assert_eq!(execute_only_pkey(&a, &mut st, &mut r), PKEY_ALLOC_FAILED);
    assert!(r.denied.is_empty());
}

#[test]
fn hardware_absent_yields_the_default_key_not_a_failure() {
    for a in [X86_64, AARCH64] {
        let mut st = PkeyState::new(&a);
        let mut r = Rights::new();
        assert_eq!(execute_only_pkey(&a, &mut st, &mut r), PKEY_DEFAULT);
        assert!(r.denied.is_empty());
    }
}

#[test]
fn the_arch_without_an_execute_only_key_never_allocates_one() {
    let a = arm_poe();
    let mut st = PkeyState::new(&a);
    let mut r = Rights::new();
    assert_eq!(execute_only_pkey(&a, &mut st, &mut r), PKEY_ALLOC_FAILED);
    assert_eq!(st.map, a.init_map, "no key may be taken");
    assert!(r.denied.is_empty());
}

#[test]
fn a_key_that_came_from_the_caller_is_never_overridden() {
    let a = x86_ospke();
    let mut st = PkeyState::new(&a);
    let mut r = Rights::new();
    let vma = VmaKeyView { pkey: 4, access_is_exec_only: true };
    for requested in [0, 1, 9, 15] {
        assert_eq!(arch_override_mprotect_pkey(&a, &mut st, true, vma, requested, &mut r), requested);
    }
    assert!(r.denied.is_empty(), "an explicit key must not trigger execute-only setup");
}

#[test]
fn a_plain_mprotect_to_execute_only_takes_the_execute_only_key() {
    let a = x86_ospke();
    let mut st = PkeyState::new(&a);
    let mut r = Rights::new();
    let vma = VmaKeyView { pkey: 0, access_is_exec_only: false };
    let k = arch_override_mprotect_pkey(&a, &mut st, true, vma, keep(), &mut r);
    assert_eq!(k, st.execute_only);
    assert!(k > 0);
}

#[test]
fn leaving_execute_only_returns_the_mapping_to_the_default_key() {
    let a = x86_ospke();
    let mut st = PkeyState::new(&a);
    let mut r = Rights::new();
    let k = execute_only_pkey(&a, &mut st, &mut r);
    let vma = VmaKeyView { pkey: k as u8, access_is_exec_only: true };
    assert_eq!(arch_override_mprotect_pkey(&a, &mut st, false, vma, keep(), &mut r), PKEY_DEFAULT);
}

#[test]
fn a_plain_mprotect_otherwise_inherits_the_vmas_own_key() {
    let a = x86_ospke();
    let mut st = PkeyState::new(&a);
    let mut r = Rights::new();
    // Not execute-only before, not execute-only after: the key is untouched.
    let vma = VmaKeyView { pkey: 6, access_is_exec_only: false };
    assert_eq!(arch_override_mprotect_pkey(&a, &mut st, false, vma, keep(), &mut r), 6);
    // Execute-only before, but NOT using the execute-only key: also untouched.
    let vma = VmaKeyView { pkey: 6, access_is_exec_only: true };
    assert_eq!(arch_override_mprotect_pkey(&a, &mut st, false, vma, keep(), &mut r), 6);
}

#[test]
fn a_failed_execute_only_setup_falls_back_to_the_vmas_key() {
    let a = x86_ospke();
    let mut st = PkeyState::new(&a);
    let mut r = Rights::new();
    r.deny_ok = false;
    let vma = VmaKeyView { pkey: 6, access_is_exec_only: false };
    assert_eq!(arch_override_mprotect_pkey(&a, &mut st, true, vma, keep(), &mut r), 6);
}

#[test]
fn the_two_arches_disagree_about_a_plain_mprotect_with_the_feature_off() {
    let mut r = Rights::new();
    let vma = VmaKeyView { pkey: 6, access_is_exec_only: false };
    // The arch with an execute-only key collapses to the default key when the
    // hardware is absent ...
    let a = X86_64;
    let mut st = PkeyState::new(&a);
    assert_eq!(arch_override_mprotect_pkey(&a, &mut st, false, vma, keep(), &mut r), PKEY_DEFAULT);
    // ... while the arch without one inherits the VMA's key with no hardware
    // test at all, feature on or off.
    for a in [AARCH64, arm_poe()] {
        let mut st = PkeyState::new(&a);
        assert_eq!(arch_override_mprotect_pkey(&a, &mut st, false, vma, keep(), &mut r), 6);
        assert_eq!(arch_override_mprotect_pkey(&a, &mut st, true, vma, keep(), &mut r), 6);
    }
    assert!(r.denied.is_empty());
}
