use super::*;

/// The defect this chain replaces: a family bound by the tagged entry and
/// absent from the raw entry answered every hosted routing test and refused
/// every real call. With one chain the equivalent defect is a family missing
/// from `ORDER`, so that is what this asserts.
#[test]
fn order_walks_every_family_exactly_once() {
    for family in ALL { assert_eq!(walked(*family), 1, "family not walked exactly once: {family:?}"); }
    assert_eq!(ORDER.len(), ALL.len());
}

#[test]
fn all_lists_no_family_twice() {
    for (index, family) in ALL.iter().enumerate() {
        assert!(!ALL[..index].contains(family), "duplicate family in ALL: {family:?}");
    }
}

/// The twelve families the raw entry had no binding for. Pinned by name so a
/// future edit that drops one from the walk fails here rather than in a boot.
#[test]
fn the_families_the_raw_entry_refused_are_walked() {
    for family in [Family::InputRaw, Family::KeyboardRaw, Family::RawInputRaw, Family::ClipboardRaw,
                   Family::AtomRaw, Family::HookRaw, Family::StationRaw, Family::WindowRaw,
                   Family::CursorIconRaw, Family::Drag, Family::DrawIcon, Family::FontFamily] {
        assert_eq!(walked(family), 1, "family missing from the chain: {family:?}");
    }
}

/// NtUserSetCapture, NtUserGetThreadState and NtUserGetKeyboardLayout are the
/// three calls a click and a keystroke reach first; the raw entry refused all
/// three because their families were bound only by the tagged entry.
#[test]
fn the_click_and_keystroke_families_are_walked() {
    assert_eq!(walked(Family::InputRaw), 1);
    assert_eq!(walked(Family::KeyboardRaw), 1);
}

#[test]
fn the_normalized_array_covers_the_widest_admitted_call() {
    // NtUserCreateWindowEx carries seventeen Windows arguments.
    assert_eq!(MAX_ARGS, 17);
}
