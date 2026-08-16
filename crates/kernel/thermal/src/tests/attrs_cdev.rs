use super::*;
use crate::cdev::CoolingOps;
use core::sync::atomic::{AtomicU64, Ordering};

struct Fan { state: AtomicU64, max: u64 }
impl CoolingOps for Fan {
    fn max_state(&self) -> KResult<u64> { Ok(self.max) }
    fn cur_state(&self) -> KResult<u64> { Ok(self.state.load(Ordering::Relaxed)) }
    fn set_cur_state(&self, state: u64) -> KResult<()> {
        self.state.store(state, Ordering::Relaxed);
        Ok(())
    }
}

fn fan(max: u64) -> Arc<CoolingDevice> {
    Arc::new(CoolingDevice::new(0, "Fan", Arc::new(Fan { state: AtomicU64::new(0), max }), max, 0))
}

fn body(cdev: &Arc<CoolingDevice>, attr: &str, now: u64) -> String {
    String::from_utf8(show(cdev, attr, now).expect(attr)).expect("utf8")
}

#[test]
fn the_range_and_current_state_read_back() {
    let cdev = fan(4);
    assert_eq!(body(&cdev, "type", 0), "Fan\n");
    assert_eq!(body(&cdev, "max_state", 0), "4\n");
    assert_eq!(body(&cdev, "cur_state", 0), "0\n");
    assert!(cdev.set_cur_state(3, 0).is_ok());
    assert_eq!(body(&cdev, "cur_state", 0), "3\n");
}

#[test]
fn occupancy_reads_in_milliseconds_not_the_nanoseconds_it_is_measured_in() {
    assert_eq!(ns_to_ms(0), 0);
    assert_eq!(ns_to_ms(1_000_000), 1);
    assert_eq!(ns_to_ms(2_500_000), 2, "truncates rather than rounding up");
    assert_eq!(ns_to_ms(999_999), 0);

    let cdev = fan(1);
    let text = String::from_utf8(
        show(&cdev, "time_in_state_ms", 5_000_000).expect("show")).expect("utf8");
    assert_eq!(text, "state0\t5\nstate1\t0\n",
               "a nanosecond figure here would be a million-fold overstatement");
}

#[test]
fn the_transition_table_is_square_over_every_state() {
    let cdev = fan(1);
    assert!(cdev.set_cur_state(1, 0).is_ok());
    let text = body(&cdev, "trans_table", 0);
    let lines: alloc::vec::Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 4, "a title, a header and one row per state");
    assert!(lines[0].contains("From"));
    assert!(lines[1].contains("state0") && lines[1].contains("state1"));
    assert!(lines[2].starts_with("   state0 :"), "row label right-justified: {:?}", lines[2]);
    assert!(lines[2].ends_with('1'), "one transition from state 0 to state 1");
    assert_eq!(body(&cdev, "total_trans", 0), "1\n");
}

#[test]
fn a_write_to_cur_state_beyond_the_range_is_refused() {
    let cdev = fan(2);
    assert_eq!(store(&cdev, "cur_state", b"5", 0), Err(VfsError::Einval));
    assert_eq!(body(&cdev, "cur_state", 0), "0\n");
    assert_eq!(store(&cdev, "cur_state", b"nonsense", 0), Err(VfsError::Einval));
    assert_eq!(store(&cdev, "cur_state", b"2\n", 0), Ok(2));
    assert_eq!(body(&cdev, "cur_state", 0), "2\n");
}

#[test]
fn a_reset_clears_the_statistics_through_the_attribute() {
    let cdev = fan(2);
    assert!(cdev.set_cur_state(1, 0).is_ok());
    assert_eq!(body(&cdev, "total_trans", 0), "1\n");
    assert_eq!(store(&cdev, "reset", b"1", 0), Ok(1));
    assert_eq!(body(&cdev, "total_trans", 0), "0\n");
}

#[test]
fn the_write_only_and_read_only_attributes_refuse_the_wrong_direction() {
    let cdev = fan(2);
    assert_eq!(show(&cdev, "reset", 0), Err(VfsError::Eacces));
    assert_eq!(store(&cdev, "max_state", b"9", 0), Err(VfsError::Eacces));
    assert_eq!(store(&cdev, "type", b"Other", 0), Err(VfsError::Eacces));
    assert_eq!(show(&cdev, "nonexistent", 0), Err(VfsError::Enoent));
}

#[test]
fn the_published_attribute_set_and_its_modes_are_fixed() {
    let list = attrs();
    let mode = |name: &str| list.iter().find(|(attr, _)| attr == name).map(|(_, mode)| *mode);
    assert_eq!(mode("type"), Some(RO));
    assert_eq!(mode("max_state"), Some(RO));
    assert_eq!(mode("cur_state"), Some(RW));
    assert_eq!(mode("total_trans"), Some(RO));
    assert_eq!(mode("time_in_state_ms"), Some(RO));
    assert_eq!(mode("trans_table"), Some(RO));
    assert_eq!(mode("reset"), Some(WO));
}

#[test]
fn the_uevent_names_the_device_kind() {
    let cdev = fan(1);
    let env = uevent_env(&cdev);
    assert!(env.iter().any(|line| line == "DEVTYPE=thermal_cooling_device"));
    assert!(env.iter().any(|line| line == "NAME=Fan"));
}
