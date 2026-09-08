//! Which locale each service names, and what a replacement changes.

use super::*;

const STATUS_ACCESS_VIOLATION: u64 = 0xc000_0005;

#[test]
fn a_fresh_process_reports_one_locale_everywhere() {
    let locales = Locales::from_stored(0, 0, 0);
    assert_eq!(locales.locale(Which::System), locales.locale(Which::User));
    assert_eq!(locales.ui, language_of(locales.system));
    assert_eq!(locales.install_language(), language_of(locales.system));
}

#[test]
fn the_selector_picks_the_user_locale_when_set_and_the_system_one_when_clear() {
    assert_eq!(admit_locale_query(1, 0x1000), Ok(Which::User));
    assert_eq!(admit_locale_query(0, 0x1000), Ok(Which::System));
    assert_eq!(admit_locale_set(1, 0x0407), (Which::User, 0x0407));
    assert_eq!(admit_locale_set(0, 0x0407), (Which::System, 0x0407));
}

#[test]
fn any_non_zero_selector_names_the_user_locale() {
    // The selector is one byte in a register whose upper bits are not part
    // of it, and every non-zero value of it means the same thing; refusing
    // one would fail a caller that passed a perfectly ordinary true.
    assert_eq!(admit_locale_query(2, 0x1000), Ok(Which::User));
    assert_eq!(admit_locale_query(0xffff_ffff_ffff_ff01, 0x1000), Ok(Which::User));
    assert_eq!(admit_locale_query(0x7fff_0000_0000_0000, 0x1000), Ok(Which::System));
    assert_eq!(admit_locale_set(0xff, 0x0407), (Which::User, 0x0407));
}

#[test]
fn an_answer_needs_somewhere_to_go() {
    // The service writes its answer through the pointer without checking it,
    // so a caller that passes none is told its memory could not be written.
    assert_eq!(admit_locale_query(0, 0), Err(STATUS_ACCESS_VIOLATION));
    assert_eq!(admit_language_query(0), Err(STATUS_ACCESS_VIOLATION));
    assert_eq!(admit_language_query(0x1000), Ok(()));
}

#[test]
fn an_identifier_is_only_as_wide_as_its_own_field() {
    // A stub stores these arguments with a narrow store, so whatever sits
    // above them in the register belongs to nobody.
    assert_eq!(admit_locale_set(0, 0xdead_0000_0000_0407), (Which::System, 0x0407));
    assert_eq!(language_argument(0xdead_beef_0000_0407), 0x0407);
    assert_eq!(language_argument(0x0407), 0x0407);
}

#[test]
fn replacing_the_user_locale_leaves_the_system_one_alone() {
    let baseline = Locales::from_stored(0, 0, 0);
    let locales = Locales::from_stored(0, 0x0c0a, 0);
    assert_eq!(locales.locale(Which::User), 0x0c0a);
    assert_eq!(locales.locale(Which::System), baseline.system);
    assert_eq!(locales.install_language(), language_of(baseline.system));
}

#[test]
fn the_install_language_follows_the_system_locale() {
    assert_eq!(Locales::from_stored(0x0411, 0, 0).install_language(), 0x0411);
    // A locale identifier carries the sort order above its language half; the
    // install language is the language half alone.
    assert_eq!(Locales::from_stored(0x0004_0411, 0, 0).install_language(), 0x0411);
}

#[test]
fn an_unset_value_falls_back_to_the_one_beneath_it() {
    let baseline = Locales::from_stored(0, 0, 0);
    assert_eq!(Locales::from_stored(0x0411, 0, 0), Locales { system: 0x0411, user: 0x0411, ui: 0x0411 });
    assert_eq!(Locales::from_stored(0, 0x0407, 0), Locales { system: baseline.system, user: 0x0407, ui: 0x0407 });
    assert_eq!(Locales::from_stored(0x0411, 0x0407, 0x0409), Locales { system: 0x0411, user: 0x0407, ui: 0x0409 });
}
