//! System-colour overrides replace one role and leave the rest at default.
use super::*;

#[test]
fn every_role_starts_at_its_documented_default() {
    let table = SystemColorTable::new();
    assert!(table.is_default());
    for role in ROLES { assert_eq!(table.value(role), role.color()); }
}

#[test]
fn a_set_replaces_one_role_and_reports_the_previous_value() {
    let mut table = SystemColorTable::new();
    assert_eq!(table.set(SystemColor::ActiveCaption, 0x00ff_0000), SystemColor::ActiveCaption.color());
    assert_eq!(table.value(SystemColor::ActiveCaption), 0x00ff_0000);
    assert_eq!(table.set(SystemColor::ActiveCaption, 0x0000_ff00), 0x00ff_0000);
    assert!(!table.is_default());
    assert_eq!(table.value(SystemColor::InactiveCaption), SystemColor::InactiveCaption.color());
}

#[test]
fn an_override_equal_to_the_default_is_still_an_override() {
    let mut table = SystemColorTable::new();
    table.set(SystemColor::Window, SystemColor::Window.color());
    assert!(!table.is_default());
    assert_eq!(table.value(SystemColor::Window), SystemColor::Window.color());
}
