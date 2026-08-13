//! Process-context hub change service.

extern crate alloc;

use core::sync::atomic::{AtomicBool, Ordering};

use alloc::sync::Arc;

use crate::probe::{add_usb_device, address_hub_child, control_complete, Controller, UsbDevice, XhciBh, CONTROLLERS};

const HUB_RESET_RECOVERY_NS: u64 = 50_000_000;

static HUB_WORK_QUEUED: AtomicBool = AtomicBool::new(false);

#[derive(Copy, Clone)]
struct ChildRequest { topology: crate::context::DeviceTopology, portsc: u32 }

pub(crate) fn queue_hub_work() {
    if HUB_WORK_QUEUED.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_ok()
        && !sched::live::workqueue::queue_work(hub_event_work, 0)
    { HUB_WORK_QUEUED.store(false, Ordering::Release); }
}

fn hub_event_work(_arg: usize) {
    let controllers = CONTROLLERS.lock_bh::<XhciBh>().clone();
    for controller in &controllers {
        let devices = controller.state.lock_bh::<XhciBh>().devices.clone();
        for device in devices {
            let Some((events, ports, power_delay_ms)) = take_events(&device) else { continue; };
            if let Some(delay_ms) = power_delay_ms {
                for port in 1..=ports {
                    if !port_feature(controller, &device, port, crate::usb::HUB_PORT_FEATURE_POWER, true) { continue; }
                }
                hub_delay_ns(u64::from(delay_ms).saturating_mul(1_000_000));
            }
            for port in 1..=ports {
                if crate::usb::hub_port_changed(events.bytes(), port) != Some(true) { continue; }
                let Some(status) = port_status(controller, &device, port) else { continue; };
                if status.connection_changed() && !port_feature(controller, &device, port,
                    crate::usb::HUB_PORT_FEATURE_C_CONNECTION, false)
                { continue; }
                if !status.connected() { continue; }
                let Some(topology) = device.state.lock_bh::<XhciBh>().device.topology().child(port) else { continue; };
                if !port_feature(controller, &device, port, crate::usb::HUB_PORT_FEATURE_RESET, true) { continue; }
                hub_reset_recovery();
                let Some(reset_status) = port_status(controller, &device, port) else { continue; };
                if !reset_status.connected() || reset_status.resetting() || !reset_status.enabled() { continue; }
                if reset_status.reset_changed() && !port_feature(controller, &device, port,
                    crate::usb::HUB_PORT_FEATURE_C_RESET, false)
                { continue; }
                let request = ChildRequest { topology, portsc: reset_status.xhci_portsc() };
            let (mmio, command, dcbaa, irq) = {
                let controller_state = controller.state.lock_bh::<XhciBh>();
                if controller_state.devices.iter().any(|child| child.state.lock_bh::<XhciBh>().device.topology() == request.topology) { continue; }
                (Arc::clone(&controller_state.mmio), Arc::clone(&controller_state.command), Arc::clone(&controller_state._dcbaa), controller_state.irq)
            };
            let Some(child) = address_hub_child(controller.bdf, &mmio, &command, &dcbaa, irq, request.topology, request.portsc) else { continue; };
            let child = UsbDevice::new(controller, Box::new(child));
            let mut controller_state = controller.state.lock_bh::<XhciBh>();
            if !controller_state.devices.iter().any(|existing| existing.state.lock_bh::<XhciBh>().device.topology() == request.topology)
            { let _ = add_usb_device(&mut controller_state, child); }
            else { crate::probe_input::remove_hid_input(&child.state.lock_bh::<XhciBh>()); }
            }
        }
    }
    HUB_WORK_QUEUED.store(false, Ordering::Release);
    if hub_events_pending() { queue_hub_work(); }
}

fn take_events(device: &Arc<UsbDevice>) -> Option<(crate::usb::HubStatusBitmap, u8, Option<u16>)> {
    let mut state = device.state.lock_bh::<XhciBh>();
    let ports = state.device.hub_descriptor()?.ports;
    let events = state.device.take_hub_events()?;
    let power_delay_ms = state.device.take_hub_power_delay_ms();
    Some((events, ports, power_delay_ms))
}

fn port_status(controller: &Arc<Controller>, device: &Arc<UsbDevice>, port: u8) -> Option<crate::usb::HubPortStatus> {
    let (irq, completion, slot) = {
        let controller = controller.state.lock_bh::<XhciBh>();
        let mut device = device.state.lock_bh::<XhciBh>();
        let slot = device.slot;
        let completion = device.device.submit_hub_port_status(&controller.mmio, slot, port)?;
        (controller.irq, completion, slot)
    };
    if !control_complete(irq, completion, slot) { return None; }
    device.state.lock_bh::<XhciBh>().device.hub_port_status()
}

fn port_feature(controller: &Arc<Controller>, device: &Arc<UsbDevice>, port: u8, feature: u16, set: bool) -> bool {
    let (irq, completion, slot) = {
        let controller = controller.state.lock_bh::<XhciBh>();
        let mut device = device.state.lock_bh::<XhciBh>();
        let slot = device.slot;
        let Some(completion) = device.device.submit_hub_port_feature(&controller.mmio, slot, port, feature, set) else { return false; };
        (controller.irq, completion, slot)
    };
    control_complete(irq, completion, slot)
}

fn hub_reset_recovery() {
    hub_delay_ns(HUB_RESET_RECOVERY_NS);
}

fn hub_delay_ns(delay_ns: u64) {
    if delay_ns == 0 { return; }
    let wait = sched::live::WaitList::new();
    let deadline = sched::deadline::clock::now_ns().saturating_add(delay_ns);
    // SAFETY: kworker process context performs its delay without a driver lock held.
    let _ = unsafe { sched::live::wait_event(&wait, sched::WaitState::Interruptible,
        deadline, sched::deadline::clock::now_ns, || false) };
}

fn hub_events_pending() -> bool {
    let controllers = CONTROLLERS.lock_bh::<XhciBh>().clone();
    controllers.iter().any(|controller| controller.state.lock_bh::<XhciBh>().devices.iter()
        .any(|device| device.state.lock_bh::<XhciBh>().device.hub_events_pending()))
}
