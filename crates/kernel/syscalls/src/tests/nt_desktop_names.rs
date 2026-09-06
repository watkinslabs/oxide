use super::*;

#[test]
fn the_interactive_station_carries_the_name_applications_look_up() {
    assert_eq!(INTERACTIVE_STATION, "\\Windows\\WindowStations\\WinSta0");
    assert_eq!(DEFAULT_DESKTOP, "Default");
}

#[test]
fn the_desktop_name_is_a_leaf_the_bootstrap_will_accept() {
    // bootstrap_desktop joins station and desktop with a single separator and
    // rejects a name carrying its own, so this must stay a bare leaf.
    assert!(!DEFAULT_DESKTOP.contains('\\'));
    assert!(!DEFAULT_DESKTOP.contains('/'));
    assert!(!DEFAULT_DESKTOP.is_empty());
    assert_ne!(DEFAULT_DESKTOP, ".");
    assert_ne!(DEFAULT_DESKTOP, "..");
}

#[test]
fn neither_access_mask_grants_rights_that_unseat_other_processes() {
    const DELETE: u32 = 0x0001_0000;
    const WRITE_OWNER: u32 = 0x0008_0000;
    const WRITE_DAC: u32 = 0x0004_0000;
    for (name, access) in [("station", STATION_ACCESS), ("desktop", DESKTOP_ACCESS)] {
        assert_eq!(access & DELETE, 0, "{name} must not grant DELETE");
        assert_eq!(access & WRITE_OWNER, 0, "{name} must not grant WRITE_OWNER");
        assert_eq!(access & WRITE_DAC, 0, "{name} must not grant WRITE_DAC");
        assert_ne!(access, 0, "{name} must grant the rights its own use needs");
    }
}
