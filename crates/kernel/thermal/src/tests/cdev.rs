use super::*;
use core::sync::atomic::{AtomicU64, Ordering};

struct Fan { state: AtomicU64, max: u64, refuse: bool }

impl CoolingOps for Fan {
    fn max_state(&self) -> KResult<u64> { Ok(self.max) }
    fn cur_state(&self) -> KResult<u64> { Ok(self.state.load(Ordering::Relaxed)) }
    fn set_cur_state(&self, state: u64) -> KResult<()> {
        if self.refuse { return Err(VfsError::Eio); }
        self.state.store(state, Ordering::Relaxed);
        Ok(())
    }
}

fn fan(max: u64) -> (Arc<Fan>, CoolingDevice) {
    let ops = Arc::new(Fan { state: AtomicU64::new(0), max, refuse: false });
    let dev = CoolingDevice::new(0, "Fan", ops.clone(), max, 0);
    (ops, dev)
}

#[test]
fn a_state_the_device_does_not_have_is_refused_without_reaching_the_provider() {
    let (ops, dev) = fan(3);
    assert_eq!(dev.set_cur_state(4, 0), Err(VfsError::Einval));
    assert_eq!(ops.state.load(Ordering::Relaxed), 0);
    assert_eq!(dev.transitions(), 0);
    assert!(dev.set_cur_state(3, 0).is_ok());
    assert_eq!(ops.state.load(Ordering::Relaxed), 3);
}

#[test]
fn a_transition_the_provider_refuses_is_not_counted() {
    let ops = Arc::new(Fan { state: AtomicU64::new(0), max: 3, refuse: true });
    let dev = CoolingDevice::new(0, "Fan", ops, 3, 0);
    assert_eq!(dev.set_cur_state(2, 0), Err(VfsError::Eio));
    assert_eq!(dev.transitions(), 0);
    assert_eq!(dev.trans_table().iter().sum::<u64>(), 0);
}

#[test]
fn occupancy_accrues_to_the_state_the_device_was_in() {
    let (_, dev) = fan(2);
    assert!(dev.set_cur_state(1, 1_000).is_ok());
    assert!(dev.set_cur_state(2, 3_000).is_ok());
    let times = dev.time_in_state_ns(6_000);
    assert_eq!(times[0], 1_000, "off from 0 to 1000");
    assert_eq!(times[1], 2_000, "state 1 from 1000 to 3000");
    assert_eq!(times[2], 3_000, "state 2 from 3000 to the read at 6000");
}

#[test]
fn re_driving_the_same_state_accrues_time_without_counting_a_transition() {
    let (_, dev) = fan(2);
    assert!(dev.set_cur_state(1, 1_000).is_ok());
    assert!(dev.set_cur_state(1, 5_000).is_ok());
    assert_eq!(dev.transitions(), 1);
    assert_eq!(dev.time_in_state_ns(5_000)[1], 4_000);
}

#[test]
fn the_transition_table_records_which_pair_of_states_was_traversed() {
    let (_, dev) = fan(2);
    assert!(dev.set_cur_state(1, 0).is_ok());
    assert!(dev.set_cur_state(2, 0).is_ok());
    assert!(dev.set_cur_state(1, 0).is_ok());
    let table = dev.trans_table();
    let width = 3;
    assert_eq!(table[0 * width + 1], 1);
    assert_eq!(table[1 * width + 2], 1);
    assert_eq!(table[2 * width + 1], 1);
    assert_eq!(table[1 * width + 0], 0);
    assert_eq!(dev.transitions(), 3);
}

#[test]
fn a_reset_clears_the_counters_and_restarts_the_occupancy_clock() {
    let (_, dev) = fan(2);
    assert!(dev.set_cur_state(1, 1_000).is_ok());
    dev.reset_stats(4_000);
    assert_eq!(dev.transitions(), 0);
    assert!(dev.trans_table().iter().all(|count| *count == 0));
    assert_eq!(dev.time_in_state_ns(9_000)[1], 5_000, "clock restarts at the reset");
}

#[test]
fn the_device_name_is_class_scoped_not_provider_scoped() {
    let ops = Arc::new(Fan { state: AtomicU64::new(0), max: 1, refuse: false });
    let dev = CoolingDevice::new(7, "Processor", ops, 1, 0);
    assert_eq!(dev.name(), "cooling_device7");
    assert_eq!(dev.ty(), "Processor");
}
