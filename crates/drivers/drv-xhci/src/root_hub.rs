//! Process-context root-hub port change service.

extern crate alloc;

use core::sync::atomic::{AtomicBool, Ordering};

use alloc::{boxed::Box, sync::Arc};
use alloc::vec::Vec;

use crate::irq::PORT_CHANGE_WORDS;
use crate::probe::{add_usb_device, address_port_device, Controller, UsbDevice, XhciBh, CONTROLLERS};

static ROOT_WORK_QUEUED: AtomicBool = AtomicBool::new(false);
static ROOT_WORK_RESCAN: AtomicBool = AtomicBool::new(false);

enum RootReset { Complete, Pending, Failed }

/// Queue process-context root-hub discovery from the USB softirq. # C: O(1)
pub(crate) fn queue_root_work() -> bool {
    if ROOT_WORK_QUEUED.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() {
        ROOT_WORK_RESCAN.store(true, Ordering::Release);
        return true;
    }
    if sched::live::workqueue::queue_work(root_hub_work, 0) { return true; }
    ROOT_WORK_QUEUED.store(false, Ordering::Release);
    false
}
fn root_hub_work(_arg: usize) {
    #[cfg(feature = "debug-boot")]
    klog::write_raw(b"[INFO]  xhci: root work\n");
    let controllers = {
        let controllers = CONTROLLERS.lock_bh::<XhciBh>();
        controllers.clone()
    };
    #[cfg(feature = "debug-boot")]
    klog::write_raw(b"[INFO]  xhci: root controllers\n");
    for controller in controllers {
        let (changed, ports) = {
            let state = controller.state.lock_bh::<XhciBh>();
            (state.irq.take_port_changes(), state.mmio.geometry().max_ports)
        };
        #[cfg(feature = "debug-boot")]
        klog::write_raw(b"[INFO]  xhci: root snapshot\n");
        let mut added = Vec::new();
        for port in 1..=ports {
            let word = (port as usize - 1) / u64::BITS as usize;
            let bit = (port - 1) % u64::BITS as u8;
            if word < PORT_CHANGE_WORDS && changed[word] & (1u64 << bit) != 0 {
                if let Some(device) = service_port_change(&controller, port) { added.push(device); }
            }
        }
        for device in added { register_storage(&device); }
    }
    #[cfg(feature = "debug-boot")]
    klog::write_raw(b"[INFO]  xhci: root work done\n");
    ROOT_WORK_QUEUED.store(false, Ordering::Release);
    if ROOT_WORK_RESCAN.swap(false, Ordering::AcqRel) {
        let _ = queue_root_work();
    }
}

// Keep controller enumeration out of the worker dispatch frame.  The
// enumeration path owns descriptor/storage temporaries and must retain the
// kernel's fixed task-stack bound rather than becoming one LTO-sized frame.
#[inline(never)]
fn service_port_change(controller: &Arc<Controller>, port: u8) -> Option<Arc<UsbDevice>> {
    #[cfg(feature = "debug-boot")]
    klog::write_raw(b"[INFO]  xhci: root port\n");
    let status = controller.state.lock_bh::<XhciBh>().mmio.port_status(port)?;
    let connected = status & crate::ports::PORT_CONNECT != 0;
    #[cfg(feature = "debug-boot")]
    klog::write_raw(b"[INFO]  xhci: root status\n");
    if !connected || status & crate::ports::PORT_CONNECT_CHANGE != 0 {
        if !crate::detach::root_port(controller, port) { return None; }
        if !connected { return None; }
    }
    {
        let state = controller.state.lock_bh::<XhciBh>();
        if state.devices.iter().any(|device| device.state.lock_bh::<XhciBh>().device.port() == port) { return None; }
    }
    {
        let state = controller.state.lock_bh::<XhciBh>();
        let _ = state.mmio.acknowledge_nonreset_changes(port);
    }
    #[cfg(feature = "debug-boot")]
    klog::write_raw(b"[INFO]  xhci: connected port\n");
    if !matches!(reset_root_port(controller, port), RootReset::Complete) { return None; }
    let (mmio, command, dcbaa, irq) = {
        let state = controller.state.lock_bh::<XhciBh>();
        if state.devices.iter().any(|device| device.state.lock_bh::<XhciBh>().device.port() == port) { return None; }
        (Arc::clone(&state.mmio), Arc::clone(&state.command), Arc::clone(&state._dcbaa), state.irq)
    };
    let device = UsbDevice::new(controller, Box::new(address_port_device(controller.bdf, &mmio, &command, &dcbaa, irq, port)?));
    let mut state = controller.state.lock_bh::<XhciBh>();
    if state.devices.iter().any(|existing| existing.state.lock_bh::<XhciBh>().device.port() == port) {
        crate::probe_input::remove_hid_input(&device.state.lock_bh::<XhciBh>());
        return None;
    }
    Some(add_usb_device(&mut state, device))
}

fn reset_root_port(controller: &Arc<Controller>, port: u8) -> RootReset {
    let state = controller.state.lock_bh::<XhciBh>();
    let Some(protocol) = state.mmio.protocol_for_port(port) else { return RootReset::Failed; };
    if !protocol.is_usb2() { return if state.mmio.reset_usb3_port(port) { RootReset::Complete } else { RootReset::Failed }; }
    let Some(status) = state.mmio.port_status(port) else { return RootReset::Failed; };
    if crate::ports::reset_completed(status) {
        return if state.mmio.finish_usb2_reset(port) { RootReset::Complete } else { RootReset::Failed };
    }
    if status & crate::ports::PORT_RESET != 0 { return RootReset::Pending; }
    if state.mmio.request_usb2_reset(port) { RootReset::Pending } else { RootReset::Failed }
}

#[inline(never)]
fn register_storage(device: &Arc<UsbDevice>) {
    let names = crate::storage_block::register(Arc::clone(device));
    if !names.is_empty() { device.state.lock_bh::<XhciBh>().storage_names = names; }
}
