//! Every cell of both method tables and every override on top of them.
//!
//! The expected tables are written out here independently of the ones the
//! implementation uses, so a swapped cell fails rather than agreeing with
//! itself. Rows are the peer's capability, columns the local one, both in the
//! order display-only, display-yes-no, keyboard-only, no-input-output,
//! keyboard-display.

use crate::uapi::bt::{BT_SECURITY_FIPS, BT_SECURITY_MEDIUM};
use crate::uapi::smp::{
    SMP_AUTH_MITM, SMP_AUTH_NONE, SMP_IO_COUNT, SMP_IO_DISPLAY_ONLY, SMP_IO_DISPLAY_YESNO,
    SMP_IO_KEYBOARD_DISPLAY, SMP_IO_KEYBOARD_ONLY, SMP_IO_NO_INPUT_OUTPUT,
};
use crate::smp::method::*;

const EXPECT_LEGACY: [[u8; SMP_IO_COUNT]; SMP_IO_COUNT] = [
    [JUST_WORKS,  JUST_CFM,    REQ_PASSKEY, JUST_WORKS, REQ_PASSKEY],
    [JUST_WORKS,  JUST_CFM,    REQ_PASSKEY, JUST_WORKS, REQ_PASSKEY],
    [CFM_PASSKEY, CFM_PASSKEY, REQ_PASSKEY, JUST_WORKS, CFM_PASSKEY],
    [JUST_WORKS,  JUST_CFM,    JUST_WORKS,  JUST_WORKS, JUST_CFM   ],
    [CFM_PASSKEY, CFM_PASSKEY, REQ_PASSKEY, JUST_WORKS, OVERLAP    ],
];

const EXPECT_SC: [[u8; SMP_IO_COUNT]; SMP_IO_COUNT] = [
    [JUST_WORKS,  JUST_CFM,    REQ_PASSKEY, JUST_WORKS, REQ_PASSKEY],
    [JUST_WORKS,  CFM_PASSKEY, REQ_PASSKEY, JUST_WORKS, CFM_PASSKEY],
    [DSP_PASSKEY, DSP_PASSKEY, REQ_PASSKEY, JUST_WORKS, DSP_PASSKEY],
    [JUST_WORKS,  JUST_CFM,    JUST_WORKS,  JUST_WORKS, JUST_CFM   ],
    [DSP_PASSKEY, CFM_PASSKEY, REQ_PASSKEY, JUST_WORKS, CFM_PASSKEY],
];

#[test]
fn legacy_table_is_complete_and_correct() {
    for remote in 0..SMP_IO_COUNT {
        for local in 0..SMP_IO_COUNT {
            assert_eq!(table_method(false, local as u8, remote as u8),
                       EXPECT_LEGACY[remote][local],
                       "legacy local {} remote {}", local, remote);
        }
    }
}

#[test]
fn secure_connections_table_is_complete_and_correct() {
    for remote in 0..SMP_IO_COUNT {
        for local in 0..SMP_IO_COUNT {
            assert_eq!(table_method(true, local as u8, remote as u8),
                       EXPECT_SC[remote][local],
                       "sc local {} remote {}", local, remote);
        }
    }
}

#[test]
fn the_two_tables_actually_differ() {
    // Four cells separate them. If a lane ever copies one over the other this
    // is what catches it.
    let mut differing = 0;
    for remote in 0..SMP_IO_COUNT {
        for local in 0..SMP_IO_COUNT {
            if EXPECT_LEGACY[remote][local] != EXPECT_SC[remote][local] { differing += 1; }
        }
    }
    assert_eq!(differing, 7);
    for remote in 0..SMP_IO_COUNT {
        for local in 0..SMP_IO_COUNT {
            let same = table_method(false, local as u8, remote as u8)
                     == table_method(true, local as u8, remote as u8);
            assert_eq!(same, EXPECT_LEGACY[remote][local] == EXPECT_SC[remote][local],
                       "local {} remote {}", local, remote);
        }
    }
}

#[test]
fn the_table_is_not_symmetric() {
    // Reading it with the arguments the other way round is a real bug, so a
    // pair that disagrees under transposition is pinned here.
    assert_eq!(table_method(false, SMP_IO_KEYBOARD_ONLY, SMP_IO_DISPLAY_ONLY), REQ_PASSKEY);
    assert_eq!(table_method(false, SMP_IO_DISPLAY_ONLY, SMP_IO_KEYBOARD_ONLY), CFM_PASSKEY);
}

#[test]
fn an_undefined_capability_degrades_to_a_plain_confirmation() {
    let bad = SMP_IO_KEYBOARD_DISPLAY + 1;
    assert_eq!(table_method(false, bad, SMP_IO_DISPLAY_ONLY), JUST_CFM);
    assert_eq!(table_method(true, SMP_IO_DISPLAY_ONLY, bad), JUST_CFM);
    assert_eq!(table_method(true, bad, bad), JUST_CFM);
}

#[test]
fn legacy_without_a_relay_requirement_never_consults_the_table() {
    // Every capability pair collapses to a confirmation, or to nothing at all
    // when this host initiated or cannot ask.
    for remote in 0..SMP_IO_COUNT {
        for local in 0..SMP_IO_COUNT {
            let responder = legacy_method(SMP_AUTH_NONE, local as u8, remote as u8, false);
            let expect = if local as u8 == SMP_IO_NO_INPUT_OUTPUT { JUST_WORKS } else { JUST_CFM };
            assert_eq!(responder, expect, "local {} remote {}", local, remote);
            assert_eq!(legacy_method(SMP_AUTH_NONE, local as u8, remote as u8, true),
                       JUST_WORKS, "initiator local {} remote {}", local, remote);
        }
    }
}

#[test]
fn legacy_overlap_is_resolved_by_role() {
    let both = SMP_IO_KEYBOARD_DISPLAY;
    assert_eq!(table_method(false, both, both), OVERLAP);
    assert_eq!(legacy_method(SMP_AUTH_MITM, both, both, true), CFM_PASSKEY);
    assert_eq!(legacy_method(SMP_AUTH_MITM, both, both, false), REQ_PASSKEY);
}

#[test]
fn legacy_with_a_relay_requirement_follows_the_table() {
    for remote in 0..SMP_IO_COUNT {
        for local in 0..SMP_IO_COUNT {
            let m = legacy_method(SMP_AUTH_MITM, local as u8, remote as u8, false);
            let mut want = EXPECT_LEGACY[remote][local];
            if want == JUST_CFM && local as u8 == SMP_IO_NO_INPUT_OUTPUT { want = JUST_WORKS; }
            if want == OVERLAP { want = REQ_PASSKEY; }
            assert_eq!(m, want, "local {} remote {}", local, remote);
        }
    }
}

#[test]
fn secure_connections_out_of_band_overrides_everything() {
    for remote in 0..SMP_IO_COUNT {
        for local in 0..SMP_IO_COUNT {
            assert_eq!(sc_method(local as u8, remote as u8, SMP_AUTH_NONE, SMP_AUTH_NONE,
                                 true, false, true), REQ_OOB);
            assert_eq!(sc_method(local as u8, remote as u8, SMP_AUTH_MITM, SMP_AUTH_MITM,
                                 false, true, false), REQ_OOB);
        }
    }
}

#[test]
fn secure_connections_without_a_relay_requirement_skips_the_table() {
    for remote in 0..SMP_IO_COUNT {
        for local in 0..SMP_IO_COUNT {
            assert_eq!(sc_method(local as u8, remote as u8, SMP_AUTH_NONE, SMP_AUTH_NONE,
                                 false, false, false),
                       JUST_WORKS, "local {} remote {}", local, remote);
        }
    }
}

#[test]
fn secure_connections_takes_the_requirement_from_either_side() {
    let local = SMP_IO_DISPLAY_YESNO;
    let remote = SMP_IO_DISPLAY_YESNO;
    assert_eq!(sc_method(local, remote, SMP_AUTH_MITM, SMP_AUTH_NONE, false, false, false),
               CFM_PASSKEY);
    assert_eq!(sc_method(local, remote, SMP_AUTH_NONE, SMP_AUTH_MITM, false, false, false),
               CFM_PASSKEY);
    assert_eq!(sc_method(local, remote, SMP_AUTH_NONE, SMP_AUTH_NONE, false, false, false),
               JUST_WORKS);
}

#[test]
fn secure_connections_confirmation_is_skipped_by_the_initiator() {
    // A pair that lands on a plain confirmation: only the responder asks.
    let local = SMP_IO_DISPLAY_YESNO;
    let remote = SMP_IO_DISPLAY_ONLY;
    assert_eq!(table_method(true, local, remote), JUST_CFM);
    assert_eq!(sc_method(local, remote, SMP_AUTH_MITM, SMP_AUTH_NONE, false, false, false),
               JUST_CFM);
    assert_eq!(sc_method(local, remote, SMP_AUTH_MITM, SMP_AUTH_NONE, false, false, true),
               JUST_WORKS);
}

#[test]
fn secure_connections_has_no_overlap_cell_to_resolve() {
    for remote in 0..SMP_IO_COUNT {
        for local in 0..SMP_IO_COUNT {
            assert_ne!(table_method(true, local as u8, remote as u8), OVERLAP);
        }
    }
}

#[test]
fn only_the_interaction_free_methods_are_unauthenticated() {
    assert!(!method_is_authenticated(JUST_WORKS));
    assert!(!method_is_authenticated(JUST_CFM));
    for m in [REQ_PASSKEY, CFM_PASSKEY, REQ_OOB, DSP_PASSKEY] {
        assert!(method_is_authenticated(m), "method {:#x}", m);
    }
    assert_eq!(method_sec_level(JUST_WORKS), BT_SECURITY_MEDIUM);
    assert_eq!(method_sec_level(JUST_CFM), BT_SECURITY_MEDIUM);
    assert_eq!(method_sec_level(REQ_OOB), BT_SECURITY_FIPS);
    assert_eq!(method_sec_level(DSP_PASSKEY), BT_SECURITY_FIPS);
}
