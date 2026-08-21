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

/// Freeze the device at `device_key`. Success means every request drained and
/// the transport confirmed reset; otherwise the DPM walk must unwind rather
/// than snapshot an engine whose DMA ownership is uncertain.
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
    f.drained() && f.reset_confirmed
}

fn state_for(device_key: virtio::VirtioChildDeviceKey) -> Option<alloc::sync::Arc<BlkState>> {
    DEVICES.lock_bh::<sched::bh::SchedBh>()
        .iter().find(|record| same_device(record, device_key))
        .map(|record| record.state.clone())
}

/// Reset the driver-owned ring cursors while the queue remains closed. The
/// transport is still reset, so no device can observe these shadows until its
/// retained ring pages have also been zeroed and reprogrammed.
/// # C: O(queues + descriptor heads)
pub fn prepare_restore_blk(device_key: virtio::VirtioChildDeviceKey) -> bool {
    let Some(state) = state_for(device_key) else { return false };
    prepare_restore_state(&state)
}

fn prepare_restore_state(state: &BlkState) -> bool {
    for queue in state.queues() {
        let mut ring = queue.lock();
        if ring.busy || !ring.pending.is_empty() || !ring.deferred.is_empty() {
            return false;
        }
        ring.avail_idx = 0;
        ring.used_seen = 0;
        ring.free_heads.clear();
        ring.free_heads.extend(request_heads(queue.res.size));
    }
    true
}

/// Reopen submissions only after the transport has reached DRIVER_OK with all
/// retained queues installed. A failed transport restore leaves `poisoned`
/// set and the stable block publication safely returns I/O errors.
/// # C: O(queues)
pub fn unquiesce_blk(device_key: virtio::VirtioChildDeviceKey) -> bool {
    let Some(state) = state_for(device_key) else { return false };
    unquiesce_state(&state)
}

fn unquiesce_state(state: &BlkState) -> bool {
    let hhdm = hhdm();
    for queue in state.queues().filter(|queue| queue.polled) {
        suppress_queue_interrupts(hhdm, &queue.res);
    }
    core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
    state.poisoned.store(false, core::sync::atomic::Ordering::Release);
    #[cfg(target_os = "oxide-kernel")]
    wake_all_blk_waiters();
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn restore_state() -> BlkState {
        let mut state = BlkState::for_test_cfg(0);
        state.requestq = BlkQueue::new(
            virtio::VirtQueueResource::new(0, 6, 0x1000, 0x2000, 0x3000, 0x8000, 0),
            5,
            false,
        );
        state.freeze_new_io();
        state
    }

    #[test]
    fn restore_reinitializes_shadows_before_reopening_admission() {
        let state = restore_state();
        {
            let mut ring = state.requestq.lock();
            ring.avail_idx = 11;
            ring.used_seen = 9;
            ring.free_heads.clear();
        }
        assert!(prepare_restore_state(&state));
        assert!(state.frozen_for_tests(), "transport is not DRIVER_OK yet");
        {
            let ring = state.requestq.lock();
            assert_eq!((ring.avail_idx, ring.used_seen), (0, 0));
            assert_eq!(ring.free_heads, alloc::vec![0, 3]);
        }
        assert!(unquiesce_state(&state));
        assert!(!state.frozen_for_tests());
    }

    #[test]
    fn a_busy_shadow_refuses_restore_and_stays_quiesced() {
        let state = restore_state();
        state.requestq.lock().busy = true;
        assert!(!prepare_restore_state(&state));
        assert!(state.frozen_for_tests());
    }
}
