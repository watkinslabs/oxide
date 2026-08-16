// virtio-blk sleep callbacks (`32a§5` step 6, `35`).
//
// A virtio block device does not suspend and resume; it freezes and restores.
// The distinction is not naming. A suspend/resume pair assumes the device
// keeps its configuration and only stops delivering — but a virtio device is
// reset on the way down, which discards the negotiated feature set, the queue
// programming and the ring addresses. Coming back is therefore a re-probe of
// everything but the driver's own state, not a rewrite of saved registers, and
// the callbacks that carry it are freeze and restore.
//
// The two step lists below are the contract, in the reference's order. They
// are data because the ordering is the whole of the correctness: quiescing
// after the reset loses the requests that were in flight, and restarting the
// queue before the device is told it is ready submits into a ring the device
// is not reading.

/// Why a restore step refused.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PmError {
    /// Re-negotiating features and re-programming the virtqueues is the
    /// transport's work, not this driver's: the driver is handed ring
    /// addresses, it does not discover them. Reported rather than faked.
    TransportRequired,
    /// The device did not come back.
    DeviceGone,
}

/// What the sequences need of a virtio block device.
pub trait BlkPm {
    /// Run one freeze step. # C: step-defined
    fn freeze_step(&mut self, step: FreezeStep);
    /// Run one restore step. # C: step-defined
    fn restore_step(&mut self, step: RestoreStep) -> Result<(), PmError>;
}

/// One step of the freeze sequence.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FreezeStep {
    /// Refuse new submissions, so the drain below terminates.
    FreezeQueue,
    /// Stop the queue accepting work without waiting for the in-flight set.
    QuiesceQueue,
    /// Let the submission path run again against a now-quiesced queue; the
    /// two together are what block new work without deadlocking a submitter
    /// already inside it.
    UnfreezeQueue,
    /// Reset the transport. After this the device raises no interrupt and
    /// holds no ring address.
    ResetDevice,
    /// Wait out the configuration-change work the reset may have raised.
    FlushConfigWork,
    /// Release the virtqueues; their memory is re-allocated on restore.
    DeleteQueues,
}

/// One step of the restore sequence.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RestoreStep {
    /// Re-negotiate features and re-program the virtqueues from scratch.
    InitQueues,
    /// Tell the device the driver is ready; only now may it read the rings.
    DeviceReady,
    /// Let submissions through again.
    UnquiesceQueue,
}

/// The freeze order (`32a§5` step 6, downward).
pub const FREEZE_ORDER: [FreezeStep; 6] = [
    FreezeStep::FreezeQueue, FreezeStep::QuiesceQueue, FreezeStep::UnfreezeQueue,
    FreezeStep::ResetDevice, FreezeStep::FlushConfigWork, FreezeStep::DeleteQueues,
];

/// The restore order (`32a§5` step 6, upward).
pub const RESTORE_ORDER: [RestoreStep; 3] = [
    RestoreStep::InitQueues, RestoreStep::DeviceReady, RestoreStep::UnquiesceQueue,
];

/// Run the freeze sequence.
///
/// Cannot refuse: every step is a teardown, and a teardown that reports
/// failure leaves the caller with nothing useful to do and a device half down.
/// # C: O(in-flight requests)
pub fn freeze<D: BlkPm>(d: &mut D) {
    for step in FREEZE_ORDER { d.freeze_step(step); }
}

/// Run the restore sequence, stopping at the first step that refuses.
///
/// A refusal leaves the queue quiesced, which is the safe state: the block
/// layer sees a device that accepts nothing rather than one that submits into
/// a ring the device is not reading.
/// # C: O(queue setup)
pub fn restore<D: BlkPm>(d: &mut D) -> Result<(), PmError> {
    for step in RESTORE_ORDER { d.restore_step(step)?; }
    Ok(())
}

#[cfg(test)]
#[path = "pm/tests.rs"]
mod tests;
