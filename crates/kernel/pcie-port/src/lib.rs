//! PCIe port-service children and their port-owned interrupt lifetime.

#![no_std]

extern crate alloc;

use alloc::{format, sync::Arc, vec::Vec};
use sync::{Spinlock, TaskList as DriverListClass};

/// PCIe port services represented by child devices. # C: O(1)
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Service { Pme = 0, Aer = 1, Hotplug = 2, Dpc = 3, Bandwidth = 4 }

impl Service {
    /// Bit in the port's discovered service mask. # C: O(1)
    pub const fn bit(self) -> u32 { 1u32 << self as u8 }
}

/// One mask of services reported by a PCIe root port or event collector.
pub type ServiceMask = u32;
/// All service bits this owner understands.
pub const SERVICE_MASK_ALL: ServiceMask = Service::Pme.bit() | Service::Aer.bit()
    | Service::Hotplug.bit() | Service::Dpc.bit() | Service::Bandwidth.bit();
const SERVICES: [Service; 5] = [Service::Pme, Service::Aer, Service::Hotplug, Service::Dpc, Service::Bandwidth];

/// An enabled service child, retaining the hardware interrupt message number
/// selected by the port capability. # C: O(1)
pub struct Child { pub service: Service, pub message_number: u8, pub device: Arc<drv::Device> }

/// Canonical owner for all service children of one PCIe port. The exact PCI
/// parent object prevents BDF reuse from moving a child onto a new function.
pub struct Port {
    root_bdf: pci::Bdf,
    parent: Arc<drv::Device>,
    service_mask: ServiceMask,
    children: Vec<Child>,
    bindings: Spinlock<Vec<pci_irq::Binding>, DriverListClass>,
}

static PORTS: Spinlock<Vec<Arc<Port>>, DriverListClass> = Spinlock::new(Vec::new());

/// Publish every enabled port-service child under `parent`. `messages` is
/// indexed by [`Service`] and must be read from the owning PCIe capability;
/// no service control or status register is changed here. # C: O(services)
pub fn publish(root_bdf: pci::Bdf, parent: Arc<drv::Device>, service_mask: ServiceMask,
    messages: [u8; 5]) -> Result<Arc<Port>, drv::Error> {
    if parent.bus != "pci" || service_mask & !SERVICE_MASK_ALL != 0 { return Err(drv::Error::Invalid); }
    if PORTS.lock().iter().any(|port| port.root_bdf == root_bdf) { return Err(drv::Error::Busy); }
    let mut children = Vec::new();
    for service in SERVICES {
        if service_mask & service.bit() == 0 { continue; }
        let child = Arc::new(drv::Device::new("pcie-port", child_addr(root_bdf, service), 0, 0, 0)
            .with_parent("pci", parent.addr.clone()));
        match drv::try_device_add_with_parent(Arc::clone(&child), &parent) {
            Ok(_) => children.push(Child { service, message_number: messages[service as usize], device: child }),
            Err(error) => { for child in children.iter().rev() { drv::device_del(&child.device); } return Err(error); }
        }
    }
    if children.is_empty() { return Err(drv::Error::Invalid); }
    let port = Arc::new(Port { root_bdf, parent, service_mask, children, bindings: Spinlock::new(Vec::new()) });
    let inserted = {
        let mut ports = PORTS.lock();
        if ports.iter().any(|entry| entry.root_bdf == root_bdf) { false }
        else { ports.push(Arc::clone(&port)); true }
    };
    if !inserted {
        for child in port.children.iter().rev() { drv::device_del(&child.device); }
        return Err(drv::Error::Busy);
    }
    Ok(port)
}

/// Return the canonical live port owner for `root_bdf`. # C: O(ports)
pub fn find(root_bdf: pci::Bdf) -> Option<Arc<Port>> {
    PORTS.lock().iter().find(|port| port.root_bdf == root_bdf).cloned()
}

/// Return the canonical port that owns the named service child. # C: O(ports)
pub fn service_port(child: &drv::Device, service: Service) -> Option<Arc<Port>> {
    PORTS.lock().iter().find(|port| port.children.iter().any(|entry|
        entry.service == service && core::ptr::eq(entry.device.as_ref(), child))).cloned()
}

/// Remove children in reverse creation order, then release every vector
/// binding retained by the port. # C: O(services + vectors)
pub fn remove(port: &Arc<Port>) {
    let removed = {
        let mut ports = PORTS.lock();
        let Some(index) = ports.iter().position(|entry| Arc::ptr_eq(entry, port)) else { return; };
        ports.remove(index)
    };
    for child in removed.children.iter().rev() { drv::device_del(&child.device); }
    for binding in core::mem::take(&mut *removed.bindings.lock()) { binding.release(); }
}

impl Port {
    /// Root-complex BDF that owns these service children. # C: O(1)
    pub const fn root_bdf(&self) -> pci::Bdf { self.root_bdf }
    /// Exact PCI model parent retained for the child lifetime. # C: O(1)
    pub fn parent(&self) -> &Arc<drv::Device> { &self.parent }
    /// Discovered service mask retained by this canonical owner. # C: O(1)
    pub const fn service_mask(&self) -> ServiceMask { self.service_mask }
    /// Service child and hardware message-number selection. # C: O(services)
    pub fn child(&self, service: Service) -> Option<&Child> { self.children.iter().find(|child| child.service == service) }
    /// Retain a PCI-core vector binding until port removal. The caller must
    /// bind a handler before transferring it here. # C: O(1)
    pub fn retain_binding(&self, binding: pci_irq::Binding) { self.bindings.lock().push(binding); }
}

fn child_addr(bdf: pci::Bdf, service: Service) -> alloc::string::String {
    format!("{:04x}:{:02x}:{:02x}.{}:pcie{}", bdf.segment, bdf.bus, bdf.device, bdf.function, service as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn children_retain_parent_mask_and_message_selection() {
        let bdf = pci::Bdf { segment: 0, bus: 0, device: 1, function: 0 };
        let parent = Arc::new(drv::Device::new("pci", format!("{:04x}:{:02x}:{:02x}.{}", bdf.segment, bdf.bus, bdf.device, bdf.function), 1, 2, 0));
        let parent = drv::try_device_add(parent).expect("parent");
        let port = publish(bdf, Arc::clone(&parent), Service::Aer.bit() | Service::Dpc.bit(), [0, 3, 0, 5, 0]).expect("port");
        assert_eq!(port.root_bdf(), bdf);
        assert!(Arc::ptr_eq(port.parent(), &parent));
        assert_eq!(port.service_mask(), Service::Aer.bit() | Service::Dpc.bit());
        assert_eq!(port.child(Service::Aer).map(|child| child.message_number), Some(3));
        assert_eq!(port.child(Service::Dpc).map(|child| child.message_number), Some(5));
        remove(&port);
        assert!(find(bdf).is_none());
        assert!(drv::devices().into_iter().all(|device| device.bus != "pcie-port"));
        drv::device_del(&parent);
    }
}
