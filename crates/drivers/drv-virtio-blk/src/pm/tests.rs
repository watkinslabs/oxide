// The freeze/restore sequence contract (`32a§5` step 6). The order is the
// whole of the correctness, so it is what is tested: a reset before the queue
// is quiesced loses the in-flight set, and a queue restarted before the device
// is told the driver is ready submits into a ring nothing is reading.

use alloc::vec::Vec;

use super::*;

#[derive(Default)]
struct Fake {
    freezes: Vec<FreezeStep>,
    restores: Vec<RestoreStep>,
    /// Restore step that refuses, if any.
    fail_at: Option<RestoreStep>,
}

impl BlkPm for Fake {
    fn freeze_step(&mut self, step: FreezeStep) { self.freezes.push(step); }
    fn restore_step(&mut self, step: RestoreStep) -> Result<(), PmError> {
        self.restores.push(step);
        if self.fail_at == Some(step) { Err(PmError::TransportRequired) } else { Ok(()) }
    }
}

#[test]
fn the_freeze_runs_every_step_in_order() {
    let mut f = Fake::default();
    freeze(&mut f);
    assert_eq!(f.freezes, FREEZE_ORDER.to_vec());
}

#[test]
fn the_queue_is_quiesced_before_the_device_is_reset() {
    let i = |s: FreezeStep| FREEZE_ORDER.iter().position(|x| *x == s).unwrap();
    assert!(i(FreezeStep::FreezeQueue) < i(FreezeStep::QuiesceQueue));
    assert!(i(FreezeStep::QuiesceQueue) < i(FreezeStep::ResetDevice),
            "a reset before the drain loses every request in flight");
    assert!(i(FreezeStep::UnfreezeQueue) < i(FreezeStep::ResetDevice));
}

#[test]
fn the_queues_are_released_only_after_the_reset_and_the_flush() {
    let i = |s: FreezeStep| FREEZE_ORDER.iter().position(|x| *x == s).unwrap();
    assert!(i(FreezeStep::ResetDevice) < i(FreezeStep::FlushConfigWork));
    assert!(i(FreezeStep::FlushConfigWork) < i(FreezeStep::DeleteQueues),
            "freeing a ring the device may still be reading is a use-after-free");
    assert_eq!(FREEZE_ORDER.last(), Some(&FreezeStep::DeleteQueues));
}

#[test]
fn the_restore_runs_every_step_in_order() {
    let mut f = Fake::default();
    assert_eq!(restore(&mut f), Ok(()));
    assert_eq!(f.restores, RESTORE_ORDER.to_vec());
}

#[test]
fn the_queue_restarts_only_after_the_device_is_told_the_driver_is_ready() {
    let i = |s: RestoreStep| RESTORE_ORDER.iter().position(|x| *x == s).unwrap();
    assert!(i(RestoreStep::InitQueues) < i(RestoreStep::DeviceReady));
    assert!(i(RestoreStep::DeviceReady) < i(RestoreStep::UnquiesceQueue));
    assert_eq!(RESTORE_ORDER.last(), Some(&RestoreStep::UnquiesceQueue));
}

#[test]
fn a_restore_stops_at_the_first_step_that_refuses() {
    for (n, step) in RESTORE_ORDER.iter().enumerate() {
        let mut f = Fake { fail_at: Some(*step), ..Default::default() };
        assert_eq!(restore(&mut f), Err(PmError::TransportRequired), "at {step:?}");
        assert_eq!(f.restores, RESTORE_ORDER[..=n].to_vec(),
                   "a refusal must not run the steps below it");
    }
}

#[test]
fn a_refused_restore_leaves_the_queue_quiesced() {
    // Reaching `UnquiesceQueue` is the only thing that lets submissions
    // through, so a sequence that stopped short cannot have run it.
    for step in [RestoreStep::InitQueues, RestoreStep::DeviceReady] {
        let mut f = Fake { fail_at: Some(step), ..Default::default() };
        assert!(restore(&mut f).is_err());
        assert!(!f.restores.contains(&RestoreStep::UnquiesceQueue));
    }
}

#[test]
fn the_two_sequences_are_not_each_others_reverse() {
    // Recorded because it is the difference between this device and a UART: a
    // virtio restore re-probes rather than replaying saved registers, so it
    // has fewer steps and none of them undoes a named freeze step.
    assert_eq!(FREEZE_ORDER.len(), 6);
    assert_eq!(RESTORE_ORDER.len(), 3);
}
