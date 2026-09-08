//! Which locale each service names, and what a replacement changes.

use super::*;

const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;

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
    assert_eq!(admit_locale_set(1, 0x0407), Ok((Which::User, 0x0407)));
    assert_eq!(admit_locale_set(0, 0x0407), Ok((Which::System, 0x0407)));
}

#[test]
fn a_selector_that_is_not_a_boolean_is_refused() {
    assert_eq!(admit_locale_query(2, 0x1000), Err(STATUS_INVALID_PARAMETER));
    assert_eq!(admit_locale_set(0xff, 0x0407), Err(STATUS_INVALID_PARAMETER));
}

#[test]
fn an_answer_needs_somewhere_to_go() {
    assert_eq!(admit_locale_query(0, 0), Err(STATUS_INVALID_PARAMETER));
    assert_eq!(admit_language_query(0), Err(STATUS_INVALID_PARAMETER));
    assert_eq!(admit_language_query(0x1000), Ok(()));
}

#[test]
fn identifiers_wider_than_their_field_name_nothing() {
    assert_eq!(admit_locale_set(0, 1 << 32), Err(STATUS_INVALID_PARAMETER));
    assert_eq!(admit_language_set(1 << 16), Err(STATUS_INVALID_PARAMETER));
    assert_eq!(admit_language_set(0x0407), Ok(0x0407));
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
