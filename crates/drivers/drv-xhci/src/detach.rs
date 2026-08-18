//! Process-context USB topology teardown.

extern crate alloc;

use alloc::{string::String, sync::Arc, vec::Vec};

use crate::context::DeviceTopology;
use crate::probe::{disable_slot, Controller, UsbDevice, XhciBh};

/// Disconnect every device below one physical root port. # Ctx: process # Sleeps: yes
pub(crate) fn root_port(controller: &Arc<Controller>, port: u8) -> bool {
    detach(controller, |topology| topology.root_port == port)
}

/// Disconnect one hub-port child and every device below that child. # Ctx: process # Sleeps: yes
pub(crate) fn branch(controller: &Arc<Controller>, topology: DeviceTopology) -> bool {
    detach(controller, |candidate| topology.contains(candidate))
}

fn detach(controller: &Arc<Controller>, matches: impl Fn(DeviceTopology) -> bool) -> bool {
    let mut devices: Vec<Arc<UsbDevice>> = controller.state.lock_bh::<XhciBh>().devices.iter()
        .filter(|device| matches(device.state.lock_bh::<XhciBh>().device.topology()))
        .cloned().collect();
    devices.sort_unstable_by_key(|device| core::cmp::Reverse(device.state.lock_bh::<XhciBh>().device.topology().depth()));
    for device in devices {
        if !detach_one(controller, &device) { return false; }
    }
    true
}

fn detach_one(controller: &Arc<Controller>, device: &Arc<UsbDevice>) -> bool {
    let names: Vec<String> = device.state.lock_bh::<XhciBh>().storage_names.iter()
        .map(|name| String::from(name.as_str())).collect();
    let mut detaches = Vec::new();
    for name in names {
        let Some(detach) = block::registry::begin_forced_detach(&name) else {
            let removed: Vec<String> = detaches.iter()
                .map(|detach: &block::registry::ForcedDetach| String::from(detach.name())).collect();
            device.state.lock_bh::<XhciBh>().storage_names.retain(|name| {
                !removed.iter().any(|removed| removed == name.as_str())
            });
            for detach in detaches { detach.wait_for_drain(); }
            return false;
        };
        detaches.push(detach);
    }
    if !detaches.is_empty() {
        device.state.lock_bh::<XhciBh>().storage_names.clear();
        for detach in detaches { detach.wait_for_drain(); }
    }
    crate::probe_input::remove_hid_input(&device.state.lock_bh::<XhciBh>());
    let mut state = controller.state.lock_bh::<XhciBh>();
    let Some(index) = state.devices.iter().position(|present| Arc::ptr_eq(present, device)) else { return true; };
    let device = state.devices.remove(index);
    let slot = device.state.lock_bh::<XhciBh>().slot;
    let crate::probe::ControllerState { mmio, command, irq, .. } = &mut *state;
    disable_slot(mmio, command, *irq, slot);
    true
}
