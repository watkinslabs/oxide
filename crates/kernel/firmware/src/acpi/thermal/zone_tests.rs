use super::*;
use alloc::sync::Arc;

struct Cooling;
impl thermal::CoolingOps for Cooling {
    fn max_state(&self) -> vfs::KResult<u64> { Ok(3) }
    fn cur_state(&self) -> vfs::KResult<u64> { Ok(0) }
    fn set_cur_state(&self, _state: u64) -> vfs::KResult<()> { Ok(()) }
}

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

#[test]
fn an_acpi_binding_uses_the_firmware_object_not_the_class_visible_type() {
    let cdev = CoolingDevice::with_binding(0, "Processor", Some("\\_PR.CPU0"), Arc::new(Cooling), 3, 0);
    assert!(matches_path(&alloc::vec![String::from("\\_PR.CPU0")], &cdev));
    assert!(!matches_path(&alloc::vec![String::from("\\_PR.CPU1")], &cdev));
}
