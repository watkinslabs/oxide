// Protection-key access-permission ladder, both arch shapes. Every
// expectation is the verified kernel behaviour for that arch, not a
// generalisation from one of them.

use super::*;
use crate::address_space::pkeys::{AARCH64, PkeyArch, X86_64};

/// A descriptor whose rights register IS live, for each arch shape.
fn x86_ospke() -> PkeyArch { PkeyArch { max_pkey: 16, ..X86_64 } }
fn arm_poe() -> PkeyArch { PkeyArch { alloc_checks_hw: false, ..AARCH64 } }

/// Records what the ladder asked the register, and denies everything.
fn deny(seen: &core::cell::Cell<Option<(u8, bool, bool)>>) -> impl FnOnce(u8, bool, bool) -> bool + '_ {
    move |k, w, x| { seen.set(Some((k, w, x))); false }
}

#[test]
fn hardware_absent_permits_everything_without_consulting_a_register() {
    let seen = core::cell::Cell::new(None);
    for a in [X86_64, AARCH64] {
        assert!(!a.pkeys_enabled());
        for (w, x, f) in [(false, false, false), (true, false, false), (false, true, false)] {
            assert!(vma_access_permitted(&a, 3, w, x, f, deny(&seen)));
        }
    }
    assert_eq!(seen.get(), None, "no register may be read when the feature is off");
}

#[test]
fn a_foreign_mapping_is_never_key_checked() {
    let seen = core::cell::Cell::new(None);
    for a in [x86_ospke(), arm_poe()] {
        assert!(vma_access_permitted(&a, 5, true, false, true, deny(&seen)));
    }
    assert_eq!(seen.get(), None);
}

#[test]
fn instruction_fetch_is_key_checked_on_one_arch_and_not_the_other() {
    // The register with no execute term cannot deny a fetch, so the ladder
    // returns before reading it...
    let seen = core::cell::Cell::new(None);
    assert!(vma_access_permitted(&x86_ospke(), 5, false, true, false, deny(&seen)));
    assert_eq!(seen.get(), None);
    // ... while the register that HAS one must be consulted, and can refuse.
    let seen = core::cell::Cell::new(None);
    assert!(!vma_access_permitted(&arm_poe(), 5, false, true, false, deny(&seen)));
    assert_eq!(seen.get(), Some((5, false, true)));
}

#[test]
fn read_and_write_reach_the_register_with_the_access_kind_intact() {
    for a in [x86_ospke(), arm_poe()] {
        let seen = core::cell::Cell::new(None);
        assert!(!vma_access_permitted(&a, 7, false, false, false, deny(&seen)));
        assert_eq!(seen.get(), Some((7, false, false)));
        let seen = core::cell::Cell::new(None);
        assert!(!vma_access_permitted(&a, 7, true, false, false, deny(&seen)));
        assert_eq!(seen.get(), Some((7, true, false)), "the write term must survive the ladder");
    }
}

#[test]
fn a_permitting_register_permits() {
    for a in [x86_ospke(), arm_poe()] {
        assert!(vma_access_permitted(&a, 2, true, false, false, |_, _, _| true));
    }
}

#[test]
fn the_foreign_test_outranks_the_register_but_not_the_feature_test() {
    // Ordering: feature, then execute, then foreign, then the register. A
    // foreign EXECUTE access on the arch that checks fetches must still be
    // permitted, which only holds if foreign is tested before the register.
    let seen = core::cell::Cell::new(None);
    assert!(vma_access_permitted(&arm_poe(), 1, false, true, true, deny(&seen)));
    assert_eq!(seen.get(), None);
}
