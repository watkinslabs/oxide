// The freeze sequence bound to the live request engine (`32a§5` step 6).
//
// A shim by design (`53`): the order lives in `crate::pm`, this only says what
// each step means for a `BlkState`. The two flags the walk carries between
// steps sit here rather than on `BlkState` — they are per-transition, and a
// device that is not mid-freeze has no opinion about them.

use super::*;
use crate::pm::{BlkPm, FreezeStep, PmError, RestoreStep};

/// One device across one freeze.
pub struct BlkFreeze<'a> {
    dev: &'a BlkState,
    /// Whether every queue reached idle before the reset.
    idle: bool,
    /// Whether the transport confirmed the reset took effect. Only then may a
    /// request's DMA buffer be released — an unconfirmed reset leaves the
    /// device possibly still writing into it.
    reset_confirmed: bool,
}

impl<'a> BlkFreeze<'a> {
    /// Begin a freeze of `dev`. # C: O(1)
    pub fn new(dev: &'a BlkState) -> Self {
        BlkFreeze { dev, idle: false, reset_confirmed: false }
    }
    /// Whether every queue drained before the reset. A false here is a
    /// quarantined request, not a failure: the freeze still completes.
    /// # C: O(1)
    pub fn drained(&self) -> bool { self.idle }
}

impl BlkPm for BlkFreeze<'_> {
    /// # C: O(in-flight requests)
    fn freeze_step(&mut self, step: FreezeStep) {
        match step {
            FreezeStep::FreezeQueue => self.dev.freeze_new_io(),
            FreezeStep::QuiesceQueue => self.idle = self.dev.wait_idle_for_remove(),
            // The submission path is gated by the one poison flag the first
            // step set, so there is no second gate to lift here.
            FreezeStep::UnfreezeQueue => {}
            FreezeStep::ResetDevice => self.reset_confirmed = self.dev.reset_common_cfg(),
            FreezeStep::FlushConfigWork => {
                self.dev.cancel_owned_requests(self.reset_confirmed);
                #[cfg(target_os = "oxide-kernel")]
                wake_all_blk_waiters();
            }
            // The rings are the transport's allocation and are released when
            // it tears the child down; a freeze hands them back through the
            // same path a remove does.
            FreezeStep::DeleteQueues => {}
        }
    }

    /// # C: O(1)
    fn restore_step(&mut self, step: RestoreStep) -> Result<(), PmError> {
        match step {
            // Re-negotiation and queue programming belong to the transport,
            // which hands this driver finished ring addresses. Reaching for
            // them here would be a second, disagreeing copy of the transport's
            // bring-up.
            RestoreStep::InitQueues => Err(PmError::TransportRequired),
            RestoreStep::DeviceReady | RestoreStep::UnquiesceQueue => Ok(()),
        }
    }
}

/// Freeze the device at `device_key`. Returns false when no such device is
/// registered.
/// # C: O(in-flight requests)
pub fn freeze_blk(device_key: virtio::VirtioChildDeviceKey) -> bool {
    let state = DEVICES.lock_bh::<sched::bh::SchedBh>()
        .iter().find(|d| same_device(d, device_key)).map(|d| d.state.clone());
    let Some(state) = state else { return false };
    let mut f = BlkFreeze::new(&state);
    crate::pm::freeze(&mut f);
    if !f.drained() {
        klog::write_raw(b"[BLK-FREEZE] reset with busy request quarantined\n");
    }
    true
}
