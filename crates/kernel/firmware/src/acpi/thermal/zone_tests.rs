use super::*;

#[test]
fn a_zone_reports_the_kind_its_firmware_object_is_named_after() {
    assert_eq!(zone_type("\\_TZ.TZ00"), "tz00");
    assert_eq!(zone_type("\\_TZ.THRM"), "thrm");
    assert_eq!(zone_type("TZ01"), "tz01");
    assert_eq!(zone_type(""), "acpitz");
    assert_eq!(zone_type("\\_TZ._"), "acpitz",
               "a name with nothing left after the leading marks is not a kind");
}

#[test]
fn the_kind_is_short_enough_for_the_class_to_publish() {
    assert!(zone_type("\\_TZ.TZ00").len() <= thermal::limits::NAME_LEN);
}
