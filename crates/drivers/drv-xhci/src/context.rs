//! Linux-shaped xHCI Address Device input-context construction.

extern crate alloc;

use alloc::vec::Vec;

const INPUT_CONTROL_CONTEXT: usize = 0;
const SLOT_CONTEXT: usize = 1;
const EP0_CONTEXT: usize = 2;
const ADD_SLOT_AND_EP0: u32 = 0x3;
const SLOT_LAST_CONTEXT_EP0: u32 = 1 << 27;
const SLOT_ROOT_HUB_PORT_SHIFT: u32 = 16;
const SLOT_SPEED_SHIFT: u32 = 20;
const SLOT_ROUTE_STRING_MASK: u32 = 0x000f_ffff;
const EP0_TYPE_CONTROL: u32 = 4 << 3;
const EP0_ERROR_COUNT: u32 = 3 << 1;
const EP0_DEQUEUE_CYCLE: u64 = 1;
const EP0_AVERAGE_TRB: u32 = 8;
const EP0_FLAG: u32 = 1 << 1;
const EP_STATE_MASK: u32 = 0x7;
const MAX_PACKET_MASK: u32 = 0xffff << 16;
const SLOT_CONTEXT_ENTRIES_MASK: u32 = 0x1f << 27;
const SLOT_HUB: u32 = 1 << 26;
const SLOT_MTT: u32 = 1 << 25;
const SLOT_MAX_PORTS_SHIFT: u32 = 24;
const TT_THINK_TIME_SHIFT: u32 = 16;
const EP_ERROR_COUNT: u32 = 3 << 1;
const EP_TYPE_BULK_OUT: u32 = 2 << 3;
const EP_TYPE_INTERRUPT_OUT: u32 = 3 << 3;
const EP_TYPE_BULK_IN: u32 = 6 << 3;
const EP_TYPE_INTERRUPT_IN: u32 = 7 << 3;

/// One dword in a controller input-context DMA region. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ContextWord { pub offset: usize, pub value: u32 }

/// xHCI-visible position of a device below one physical root-hub port.
/// `route` contains one four-bit downstream-port nibble per hub tier, least
/// significant nibble nearest the root. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DeviceTopology { pub root_port: u8, pub route: u32 }

impl DeviceTopology {
    /// Root-attached device topology. # C: O(1)
    pub const fn root(root_port: u8) -> Option<Self> {
        if root_port == 0 { None } else { Some(Self { root_port, route: 0 }) }
    }

    /// Descend through one hub port, preserving xHCI route-string order.
    /// # C: O(1)
    pub const fn child(self, hub_port: u8) -> Option<Self> {
        if hub_port == 0 || hub_port > 15 || self.route & 0xf0000 != 0 { return None; }
        Some(Self { root_port: self.root_port, route: (self.route << 4) | hub_port as u32 })
    }

    /// Whether `self` names `candidate` or one of its physical descendants.
    /// # C: O(hub depth)
    pub const fn contains(self, candidate: Self) -> bool {
        if self.root_port != candidate.root_port { return false; }
        let mut route = candidate.route;
        loop {
            if route == self.route { return true; }
            if route == 0 { return false; }
            route >>= 4;
        }
    }

    /// Number of downstream-hub links below the root port. # C: O(hub depth)
    pub const fn depth(self) -> u8 {
        let mut route = self.route;
        let mut depth = 0;
        while route != 0 { depth += 1; route >>= 4; }
        depth
    }
}

/// Endpoint transfer type represented by an xHCI endpoint context. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum EndpointType { Bulk, Interrupt }

/// One endpoint descriptor normalized for Configure Endpoint context creation. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct EndpointConfig { pub address: u8, pub max_packet: u16, pub interval: u8, pub kind: EndpointType, pub ring_pa: u64 }

/// Exact dword writes for a Linux-shaped Address Device input context. # C: O(1)
pub fn address_device_words(context_bytes: u8, port: u8, portsc: u32, ep0_ring_pa: u64) -> Option<[ContextWord; 7]> {
    address_device_topology_words(context_bytes, DeviceTopology::root(port)?, portsc, ep0_ring_pa)
}

/// Exact Address Device context writes for a root or hub-descended device.
/// # C: O(1)
pub fn address_device_topology_words(context_bytes: u8, topology: DeviceTopology, portsc: u32, ep0_ring_pa: u64) -> Option<[ContextWord; 7]> {
    let stride = context_bytes as usize;
    if !matches!(stride, 32 | 64) || topology.root_port == 0 || topology.route & !SLOT_ROUTE_STRING_MASK != 0 || ep0_ring_pa & 0xf != 0 { return None; }
    let speed = (portsc & crate::ports::PORT_SPEED_MASK) >> 10;
    let max_packet = match speed { 1 => 64, 2 => 8, 3 => 64, 4 | 5 => 512, _ => return None };
    let slot = SLOT_CONTEXT * stride;
    let ep0 = EP0_CONTEXT * stride;
    Some([
        ContextWord { offset: INPUT_CONTROL_CONTEXT * stride + 4, value: ADD_SLOT_AND_EP0 },
        ContextWord { offset: slot, value: SLOT_LAST_CONTEXT_EP0 | (speed << SLOT_SPEED_SHIFT) | topology.route },
        ContextWord { offset: slot + 4, value: (topology.root_port as u32) << SLOT_ROOT_HUB_PORT_SHIFT },
        ContextWord { offset: ep0 + 4, value: EP0_TYPE_CONTROL | EP0_ERROR_COUNT | (max_packet << 16) },
        ContextWord { offset: ep0 + 8, value: ep0_ring_pa as u32 | EP0_DEQUEUE_CYCLE as u32 },
        ContextWord { offset: ep0 + 12, value: (ep0_ring_pa >> 32) as u32 },
        ContextWord { offset: ep0 + 16, value: EP0_AVERAGE_TRB },
    ])
}

/// Build the Input Control, Slot, and endpoint-zero contexts for Address Device.
/// `bytes` must be a controller-owned, zeroed input-context region. # C: O(1)
pub fn address_device(bytes: &mut [u8], context_bytes: u8, port: u8, portsc: u32, ep0_ring_pa: u64) -> bool {
    let stride = context_bytes as usize;
    if bytes.len() < (EP0_CONTEXT + 1) * stride { return false; }
    let Some(words) = address_device_words(context_bytes, port, portsc, ep0_ring_pa) else { return false; };
    // xHCI context fields are little-endian; supported controller targets are LE.
    for word in words { put32(bytes, word.offset, word.value); }
    true
}

/// Exact writes for Linux's post-descriptor EP0 Evaluate Context update. # C: O(1)
pub fn evaluate_ep0_words(context_bytes: u8, output_ep0: [u32; 5], max_packet: u16) -> Option<[ContextWord; 7]> {
    let stride = context_bytes as usize;
    if !matches!(stride, 32 | 64) || !matches!(max_packet, 8 | 16 | 32 | 64 | 512) { return None; }
    let ep0 = EP0_CONTEXT * stride;
    let words = [
        ContextWord { offset: 0, value: 0 },
        ContextWord { offset: 4, value: EP0_FLAG },
        ContextWord { offset: ep0, value: output_ep0[0] & !EP_STATE_MASK },
        ContextWord { offset: ep0 + 4, value: output_ep0[1] & !MAX_PACKET_MASK | (u32::from(max_packet) << 16) },
        ContextWord { offset: ep0 + 8, value: output_ep0[2] },
        ContextWord { offset: ep0 + 12, value: output_ep0[3] },
        ContextWord { offset: ep0 + 16, value: output_ep0[4] },
    ];
    // Preserve an explicit array return while ensuring controller offsets fit a page.
    if words.iter().any(|word| word.offset + 4 > 4096) { return None; }
    Some(words)
}

/// Build a Linux-shaped Configure Endpoint input context for one or more endpoints. # C: O(endpoints)
pub fn configure_endpoint_words(context_bytes: u8, output_slot: [u32; 8], speed: u8, endpoints: &[EndpointConfig]) -> Option<Vec<ContextWord>> {
    let stride = context_bytes as usize;
    if !matches!(stride, 32 | 64) || !matches!(speed, 1..=5) || endpoints.is_empty() { return None; }
    let mut add_flags = 1u32;
    let mut last_id = 1u8;
    let mut normalized = Vec::with_capacity(endpoints.len());
    for endpoint in endpoints {
        let number = endpoint.address & 0x0f;
        if number == 0 || endpoint.max_packet == 0 || endpoint.ring_pa & 0xf != 0 { return None; }
        let in_dir = endpoint.address & 0x80 != 0;
        // The xHCI Device Context Index (DCI) addresses both the endpoint
        // doorbell target and the Input Control Context add flag.  An Input
        // Context has one extra leading Input Control Context, so its endpoint
        // context lives one context stride after the matching DCI in the
        // controller's output Device Context.
        let endpoint_dci = number.checked_mul(2)?.checked_add(u8::from(in_dir))?;
        let input_context = endpoint_dci.checked_add(1)?;
        if endpoint_dci > 31 || add_flags & (1 << endpoint_dci) != 0 { return None; }
        let (ty, interval, average) = match endpoint.kind {
            EndpointType::Bulk => (if in_dir { EP_TYPE_BULK_IN } else { EP_TYPE_BULK_OUT }, 0, 0),
            EndpointType::Interrupt => {
                let interval = match speed {
                    1 | 2 => {
                        let frames = u16::from(endpoint.interval).checked_mul(8)?;
                        let exponent = 15 - frames.leading_zeros() as u8;
                        exponent.clamp(3, 10)
                    }
                    3 | 4 | 5 => endpoint.interval.checked_sub(1)?,
                    _ => return None,
                };
                (if in_dir { EP_TYPE_INTERRUPT_IN } else { EP_TYPE_INTERRUPT_OUT }, interval, u32::from(endpoint.max_packet))
            }
        };
        add_flags |= 1 << endpoint_dci;
        last_id = last_id.max(endpoint_dci);
        normalized.push((input_context, ty, interval, average, endpoint.max_packet, endpoint.ring_pa));
    }
    let slot = SLOT_CONTEXT * stride;
    let mut slot0 = output_slot[0] & !SLOT_CONTEXT_ENTRIES_MASK;
    slot0 |= u32::from(last_id) << 27;
    let mut words = Vec::with_capacity(10 + normalized.len() * 5);
    words.extend_from_slice(&[
        ContextWord { offset: 0, value: 0 },
        ContextWord { offset: 4, value: add_flags },
        ContextWord { offset: slot, value: slot0 }, ContextWord { offset: slot + 4, value: output_slot[1] },
        ContextWord { offset: slot + 8, value: output_slot[2] }, ContextWord { offset: slot + 12, value: output_slot[3] },
        ContextWord { offset: slot + 16, value: output_slot[4] }, ContextWord { offset: slot + 20, value: output_slot[5] },
        ContextWord { offset: slot + 24, value: output_slot[6] }, ContextWord { offset: slot + 28, value: output_slot[7] },
    ]);
    for (input_context, ty, interval, average, max_packet, ring_pa) in normalized {
        let endpoint = input_context as usize * stride;
        words.extend_from_slice(&[
            ContextWord { offset: endpoint, value: u32::from(interval) << 16 },
            ContextWord { offset: endpoint + 4, value: EP_ERROR_COUNT | ty | (u32::from(max_packet) << 16) },
            ContextWord { offset: endpoint + 8, value: ring_pa as u32 | 1 }, ContextWord { offset: endpoint + 12, value: (ring_pa >> 32) as u32 },
            ContextWord { offset: endpoint + 16, value: average },
        ]);
    }
    Some(words)
}

/// Configure Endpoint words for one descriptor-selected HID interrupt-IN endpoint. # C: O(1)
pub fn configure_hid_words(context_bytes: u8, output_slot: [u32; 8], speed: u8, hid: crate::usb::HidInterface, ring_pa: u64) -> Option<[ContextWord; 15]> {
    configure_endpoint_words(context_bytes, output_slot, speed, &[EndpointConfig { address: hid.endpoint, max_packet: hid.max_packet, interval: hid.interval, kind: EndpointType::Interrupt, ring_pa }])?.try_into().ok()
}

/// Configure Endpoint words for one hub status-change interrupt-IN endpoint. # C: O(1)
pub fn configure_hub_words(context_bytes: u8, output_slot: [u32; 8], speed: u8, hub: crate::usb::HubInterface, ring_pa: u64) -> Option<[ContextWord; 15]> {
    configure_endpoint_words(context_bytes, output_slot, speed, &[EndpointConfig { address: hub.endpoint, max_packet: hub.max_packet, interval: hub.interval, kind: EndpointType::Interrupt, ring_pa }])?.try_into().ok()
}

/// Copy the live slot context and mark it as a hub after descriptor discovery. # C: O(1)
pub fn update_hub_slot_words(context_bytes: u8, output_slot: [u32; 8], hci_version: u16, speed: u8, device_protocol: u8, hub: crate::usb::HubDescriptor) -> Option<[ContextWord; 10]> {
    let stride = context_bytes as usize;
    if !matches!(stride, 32 | 64) || !matches!(speed, 1..=5) || hub.ports == 0 { return None; }
    let mut slot0 = output_slot[0] | SLOT_HUB;
    if device_protocol == 2 { slot0 |= SLOT_MTT; }
    else if speed == 1 { slot0 &= !SLOT_MTT; }
    let mut slot1 = output_slot[1];
    let mut tt = output_slot[2];
    if hci_version > 0x0095 {
        slot1 = (slot1 & !(0xff << SLOT_MAX_PORTS_SHIFT)) | (u32::from(hub.ports) << SLOT_MAX_PORTS_SHIFT);
        if hci_version < 0x0100 || speed == 3 { tt = (tt & !(0x3 << TT_THINK_TIME_SHIFT)) | (u32::from(hub.tt_think_time) << TT_THINK_TIME_SHIFT); }
    }
    let slot = SLOT_CONTEXT * stride;
    Some([
        ContextWord { offset: 0, value: 0 }, ContextWord { offset: 4, value: 1 },
        ContextWord { offset: slot, value: slot0 }, ContextWord { offset: slot + 4, value: slot1 },
        ContextWord { offset: slot + 8, value: tt }, ContextWord { offset: slot + 12, value: 0 },
        ContextWord { offset: slot + 16, value: output_slot[4] }, ContextWord { offset: slot + 20, value: output_slot[5] },
        ContextWord { offset: slot + 24, value: output_slot[6] }, ContextWord { offset: slot + 28, value: output_slot[7] },
    ])
}

/// Configure Endpoint words for transparent-SCSI Bulk-Only IN and OUT endpoints. # C: O(1)
pub fn configure_storage_words(context_bytes: u8, output_slot: [u32; 8], speed: u8, storage: crate::storage::MassStorageInterface, bulk_in_ring_pa: u64, bulk_out_ring_pa: u64) -> Option<Vec<ContextWord>> {
    configure_endpoint_words(context_bytes, output_slot, speed, &[
        EndpointConfig { address: storage.bulk_out, max_packet: storage.bulk_out_packet, interval: 0, kind: EndpointType::Bulk, ring_pa: bulk_out_ring_pa },
        EndpointConfig { address: storage.bulk_in, max_packet: storage.bulk_in_packet, interval: 0, kind: EndpointType::Bulk, ring_pa: bulk_in_ring_pa },
    ])
}

fn put32(bytes: &mut [u8], offset: usize, value: u32) { bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes()); }

#[cfg(test)]
mod tests {
    use super::*;
    fn word(bytes: &[u8], offset: usize) -> u32 { u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) }

    #[test]
    fn address_context_places_slot_and_ep0_at_controller_stride() {
        let mut bytes = [0u8; 256];
        assert!(address_device(&mut bytes, 64, 3, 3 << 10, 0x80_000));
        assert_eq!(word(&bytes, 4), ADD_SLOT_AND_EP0);
        assert_eq!(word(&bytes, 64), SLOT_LAST_CONTEXT_EP0 | (3 << SLOT_SPEED_SHIFT));
        assert_eq!(word(&bytes, 68), 3 << SLOT_ROOT_HUB_PORT_SHIFT);
        assert_eq!(word(&bytes, 132), EP0_TYPE_CONTROL | EP0_ERROR_COUNT | (64 << 16));
        assert_eq!(word(&bytes, 136), 0x80_001);
        assert_eq!(word(&bytes, 144), EP0_AVERAGE_TRB);
    }

    #[test]
    fn address_context_rejects_unknown_speed_or_bad_alignment() {
        let mut bytes = [0u8; 96];
        assert!(!address_device(&mut bytes, 32, 1, 0, 0x80_000));
        assert!(!address_device(&mut bytes, 32, 1, 3 << 10, 0x80_004));
        assert!(!address_device(&mut bytes, 48, 1, 3 << 10, 0x80_000));
    }

    #[test]
    fn descendant_context_keeps_root_port_and_programs_xhci_route_string() {
        let topology = DeviceTopology::root(3).unwrap().child(4).unwrap().child(2).unwrap();
        assert_eq!(topology.route, 0x42);
        let words = address_device_topology_words(64, topology, 3 << 10, 0x80_000).unwrap();
        assert_eq!(words[1], ContextWord { offset: 64, value: SLOT_LAST_CONTEXT_EP0 | (3 << SLOT_SPEED_SHIFT) | 0x42 });
        assert_eq!(words[2], ContextWord { offset: 68, value: 3 << SLOT_ROOT_HUB_PORT_SHIFT });
        assert!(DeviceTopology::root(1).unwrap().child(16).is_none());
    }

    #[test]
    fn topology_contains_exact_branch_and_orders_descendants() {
        let root = DeviceTopology::root(3).unwrap();
        let hub = root.child(4).unwrap();
        let child = hub.child(2).unwrap();
        assert!(root.contains(root));
        assert!(root.contains(child));
        assert!(hub.contains(child));
        assert!(!child.contains(hub));
        assert!(!hub.contains(DeviceTopology::root(4).unwrap()));
        assert_eq!(root.depth(), 0);
        assert_eq!(child.depth(), 2);
    }

    #[test]
    fn evaluate_context_copies_output_ep0_and_changes_only_packet_size() {
        let words = evaluate_ep0_words(64, [3, 0x0040_0026, 0x8001, 0, 8], 8).unwrap();
        assert_eq!(words[0], ContextWord { offset: 0, value: 0 });
        assert_eq!(words[1], ContextWord { offset: 4, value: EP0_FLAG });
        assert_eq!(words[2], ContextWord { offset: 128, value: 0 });
        assert_eq!(words[3], ContextWord { offset: 132, value: 0x0008_0026 });
        assert_eq!(words[4], ContextWord { offset: 136, value: 0x8001 });
        assert!(evaluate_ep0_words(32, [0; 5], 7).is_none());
        assert_eq!(evaluate_ep0_words(64, [0; 5], 512).unwrap()[3].value, 512 << 16);
    }
    #[test]
    fn hid_context_uses_xhci_endpoint_id_and_linux_interval_encoding() {
        let hid = crate::usb::HidInterface { configuration: 1, interface: 0, endpoint: 0x81, max_packet: 8, interval: 10, report_bytes: 52 };
        let words = configure_hid_words(64, [3, 4, 5, 6, 7, 8, 9, 10], 1, hid, 0x90_000).unwrap();
        assert_eq!(words[1], ContextWord { offset: 4, value: 1 | (1 << 3) });
        assert_eq!(words[2], ContextWord { offset: 64, value: (3 << 27) | 3 });
        assert_eq!(words[10], ContextWord { offset: 256, value: 6 << 16 });
        assert_eq!(words[11], ContextWord { offset: 260, value: EP_ERROR_COUNT | EP_TYPE_INTERRUPT_IN | (8 << 16) });
    }
    #[test]
    fn storage_context_uses_two_generic_bulk_endpoint_contexts() {
        let storage = crate::storage::MassStorageInterface { configuration: 1, interface: 0, bulk_in: 0x82, bulk_in_packet: 512, bulk_out: 2, bulk_out_packet: 512 };
        let words = configure_storage_words(64, [3, 4, 5, 6, 7, 8, 9, 10], 3, storage, 0xa0_000, 0x90_000).unwrap();
        assert_eq!(words[1], ContextWord { offset: 4, value: 1 | (1 << 4) | (1 << 5) });
        assert_eq!(words[2], ContextWord { offset: 64, value: (5 << 27) | 3 });
        assert!(words.contains(&ContextWord { offset: 324, value: EP_ERROR_COUNT | EP_TYPE_BULK_OUT | (512 << 16) }));
        assert!(words.contains(&ContextWord { offset: 388, value: EP_ERROR_COUNT | EP_TYPE_BULK_IN | (512 << 16) }));
        assert!(words.contains(&ContextWord { offset: 336, value: 0 }));
        assert!(configure_endpoint_words(64, [0; 8], 3, &[EndpointConfig { address: 0x81, max_packet: 8, interval: 0, kind: EndpointType::Interrupt, ring_pa: 0x90_000 }]).is_none());
    }
    #[test]
    fn hub_slot_update_copies_live_context_and_sets_linux_hub_fields() {
        let hub = crate::usb::HubDescriptor { ports: 4, power_good_ms: 20, tt_think_time: 2 };
        let words = update_hub_slot_words(64, [3 << 27, 3 << 16, 0, 7, 8, 9, 10, 11], 0x0100, 3, 2, hub).unwrap();
        assert_eq!(words[1], ContextWord { offset: 4, value: 1 });
        assert_eq!(words[2], ContextWord { offset: 64, value: (3 << 27) | SLOT_HUB | SLOT_MTT });
        assert_eq!(words[3], ContextWord { offset: 68, value: (3 << 16) | (4 << SLOT_MAX_PORTS_SHIFT) });
        assert_eq!(words[4], ContextWord { offset: 72, value: 2 << TT_THINK_TIME_SHIFT });
    }
}
