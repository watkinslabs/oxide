use super::*;

pub const VIRTIO_CHILD_BUS: &str = "virtio";
pub const VIRTIO_VENDOR_ID: u16 = 0x1AF4;
pub const VIRTIO_CHILD_CLASS: u32 = 0;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VirtioChildModelIdentity {
    pub bus: &'static str,
    pub addr: String,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class: u32,
}

impl VirtioChildModelIdentity {
    pub fn modern_from_pci(pci_vendor_id: u16, pci_device_id: u16, index: u32) -> Option<Self> {
        Some(Self {
            bus: VIRTIO_CHILD_BUS,
            addr: virtio_child_addr(index),
            vendor_id: pci_vendor_id,
            device_id: crate::modern_device_id(pci_device_id)?,
            class: VIRTIO_CHILD_CLASS,
        })
    }
}

pub fn virtio_child_addr(index: u32) -> String {
    format!("virtio{}", index)
}

pub fn virtio_child_has_parent(
    child_bus: &str,
    child_parent: Option<(&str, &str)>,
    parent_bus: &str,
    parent_addr: &str,
) -> bool {
    if child_bus != VIRTIO_CHILD_BUS {
        return false;
    }
    let Some((actual_parent_bus, actual_parent_addr)) = child_parent else {
        return false;
    };
    actual_parent_bus == parent_bus && actual_parent_addr == parent_addr
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct VirtioChildDeviceKey(u32);

impl VirtioChildDeviceKey {
    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    pub const fn from_location(location: VirtioTransportLocation) -> Self {
        Self(
            ((location.bus as u32) << 16)
                | ((location.device as u32) << 8)
                | location.function as u32,
        )
    }

    pub const fn raw(self) -> u32 {
        self.0
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct VirtioChildDriverId {
    pub name: &'static str,
    pub device_id: u16,
}

impl VirtioChildDriverId {
    pub const fn new(name: &'static str, device_id: u16) -> Self {
        Self { name, device_id }
    }

    pub fn matches_device(&self, bus: &str, vendor_id: u16, device_id: u16) -> bool {
        bus == VIRTIO_CHILD_BUS && vendor_id == VIRTIO_VENDOR_ID && device_id == self.device_id
    }
}
