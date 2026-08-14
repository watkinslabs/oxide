//! Process-context HID input registration and report-start ownership.

extern crate alloc;

use core::sync::atomic::{AtomicBool, Ordering};

use crate::probe::{Controller, UsbDevice, XhciBh, CONTROLLERS};

static HID_WORK_QUEUED: AtomicBool = AtomicBool::new(false);
static HID_WORK_RESCAN: AtomicBool = AtomicBool::new(false);

/// Queue HID input registration after USB-device publication. # C: O(1)
pub(crate) fn queue_hid_input_work() -> bool {
    if HID_WORK_QUEUED.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() {
        HID_WORK_RESCAN.store(true, Ordering::Release);
        return true;
    }
    if sched::live::workqueue::queue_work(hid_input_work, 0) { return true; }
    HID_WORK_QUEUED.store(false, Ordering::Release);
    false
}

fn hid_input_work(_arg: usize) {
    let controllers = CONTROLLERS.lock_bh::<XhciBh>().clone();
    for controller in controllers {
        let devices = controller.state.lock_bh::<XhciBh>().devices.clone();
        for device in devices { install_and_start(&controller, &device); }
    }
    HID_WORK_QUEUED.store(false, Ordering::Release);
    if HID_WORK_RESCAN.swap(false, Ordering::AcqRel) { let _ = queue_hid_input_work(); }
}

// Input registration precedes endpoint submission so a completed report is
// never delivered before its input sink is visible.
#[inline(never)]
fn install_and_start(controller: &Controller, device: &UsbDevice) {
    let _ = device.with_transport(|mmio, _, _, state| {
        if state.evdev.is_some() || state.device.hid_configuration().is_none() { return; }
        let Some(decoder) = state.decoder.as_deref() else { return; };
        let Some(evdev) = crate::probe_input::install_hid_input(controller.bdf, state.slot, Some(decoder.layout())) else { return; };
        state.evdev = Some(evdev);
        state.input_platform = Some(crate::probe_input::platform_id(controller.bdf, state.slot));
        if state.device.submit_hid_report(mmio, state.slot).is_some() {
            #[cfg(feature = "debug-boot")]
            klog::write_raw(b"[INFO]  xhci: hid interrupt armed\n");
        } else {
            crate::probe_input::remove_hid_input(state);
            state.evdev = None;
            state.input_platform = None;
        }
    });
}
