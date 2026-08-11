//! Linux-shaped xHCI Address Device input-context construction.

const INPUT_CONTROL_CONTEXT: usize = 0;
const SLOT_CONTEXT: usize = 1;
const EP0_CONTEXT: usize = 2;
const ADD_SLOT_AND_EP0: u32 = 0x3;
const SLOT_LAST_CONTEXT_EP0: u32 = 1 << 27;
const SLOT_ROOT_HUB_PORT_SHIFT: u32 = 16;
const SLOT_SPEED_SHIFT: u32 = 20;
const EP0_TYPE_CONTROL: u32 = 4 << 3;
const EP0_ERROR_COUNT: u32 = 3 << 1;
const EP0_DEQUEUE_CYCLE: u64 = 1;
const EP0_AVERAGE_TRB: u32 = 8;
const EP0_FLAG: u32 = 1 << 1;
const EP_STATE_MASK: u32 = 0x7;
const MAX_PACKET_MASK: u32 = 0xffff << 16;
const SLOT_CONTEXT_ENTRIES_MASK: u32 = 0x1f << 27;
const EP_ERROR_COUNT: u32 = 3 << 1;
const EP_TYPE_INTERRUPT_IN: u32 = 7 << 3;

/// One dword in a controller input-context DMA region. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ContextWord { pub offset: usize, pub value: u32 }

/// Exact dword writes for a Linux-shaped Address Device input context. # C: O(1)
pub fn address_device_words(context_bytes: u8, port: u8, portsc: u32, ep0_ring_pa: u64) -> Option<[ContextWord; 7]> {
    let stride = context_bytes as usize;
    if !matches!(stride, 32 | 64) || port == 0 || ep0_ring_pa & 0xf != 0 { return None; }
    let speed = (portsc & crate::ports::PORT_SPEED_MASK) >> 10;
    let max_packet = match speed { 1 => 64, 2 => 8, 3 => 64, 4 | 5 => 512, _ => return None };
    let slot = SLOT_CONTEXT * stride;
    let ep0 = EP0_CONTEXT * stride;
    Some([
        ContextWord { offset: INPUT_CONTROL_CONTEXT * stride + 4, value: ADD_SLOT_AND_EP0 },
        ContextWord { offset: slot, value: SLOT_LAST_CONTEXT_EP0 | (speed << SLOT_SPEED_SHIFT) },
        ContextWord { offset: slot + 4, value: (port as u32) << SLOT_ROOT_HUB_PORT_SHIFT },
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
pub fn evaluate_ep0_words(context_bytes: u8, output_ep0: [u32; 5], max_packet: u8) -> Option<[ContextWord; 7]> {
    let stride = context_bytes as usize;
    if !matches!(stride, 32 | 64) || !matches!(max_packet, 8 | 16 | 32 | 64) { return None; }
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

/// Linux-shaped Configure Endpoint context for one HID interrupt-IN endpoint. # C: O(1)
pub fn configure_hid_words(context_bytes: u8, output_slot: [u32; 8], speed: u8, hid: crate::usb::HidBootInterface, ring_pa: u64) -> Option<[ContextWord; 15]> {
    let stride = context_bytes as usize;
    let number = hid.endpoint & 0x0f;
    if !matches!(stride, 32 | 64) || number == 0 || hid.endpoint & 0x80 == 0 || ring_pa & 0xf != 0 { return None; }
    let endpoint_id = number.checked_mul(2)?.checked_add(1)?;
    let interval = match speed {
        1 | 2 => {
            let frames = u16::from(hid.interval).checked_mul(8)?;
            let exponent = 15 - frames.leading_zeros() as u8;
            exponent.clamp(3, 10)
        }
        3 => hid.interval.checked_sub(1)?,
        _ => return None,
    };
    let slot = SLOT_CONTEXT * stride;
    let endpoint = endpoint_id as usize * stride;
    let mut slot0 = output_slot[0] & !SLOT_CONTEXT_ENTRIES_MASK;
    slot0 |= u32::from(endpoint_id) << 27;
    Some([
        ContextWord { offset: 0, value: 0 },
        ContextWord { offset: 4, value: 1 | (1 << endpoint_id) },
        ContextWord { offset: slot, value: slot0 }, ContextWord { offset: slot + 4, value: output_slot[1] },
        ContextWord { offset: slot + 8, value: output_slot[2] }, ContextWord { offset: slot + 12, value: output_slot[3] },
        ContextWord { offset: slot + 16, value: output_slot[4] }, ContextWord { offset: slot + 20, value: output_slot[5] },
        ContextWord { offset: slot + 24, value: output_slot[6] }, ContextWord { offset: slot + 28, value: output_slot[7] },
        ContextWord { offset: endpoint, value: u32::from(interval) << 16 },
        ContextWord { offset: endpoint + 4, value: EP_ERROR_COUNT | EP_TYPE_INTERRUPT_IN | (u32::from(hid.max_packet) << 16) },
        ContextWord { offset: endpoint + 8, value: ring_pa as u32 | 1 }, ContextWord { offset: endpoint + 12, value: (ring_pa >> 32) as u32 },
        ContextWord { offset: endpoint + 16, value: u32::from(hid.max_packet) | (u32::from(hid.max_packet) << 16) },
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
    fn evaluate_context_copies_output_ep0_and_changes_only_packet_size() {
        let words = evaluate_ep0_words(64, [3, 0x0040_0026, 0x8001, 0, 8], 8).unwrap();
        assert_eq!(words[0], ContextWord { offset: 0, value: 0 });
        assert_eq!(words[1], ContextWord { offset: 4, value: EP0_FLAG });
        assert_eq!(words[2], ContextWord { offset: 128, value: 0 });
        assert_eq!(words[3], ContextWord { offset: 132, value: 0x0008_0026 });
        assert_eq!(words[4], ContextWord { offset: 136, value: 0x8001 });
        assert!(evaluate_ep0_words(32, [0; 5], 7).is_none());
    }
    #[test]
    fn hid_context_uses_xhci_endpoint_id_and_linux_interval_encoding() {
        let hid = crate::usb::HidBootInterface { configuration: 1, interface: 0, protocol: 1, endpoint: 0x81, max_packet: 8, interval: 10 };
        let words = configure_hid_words(64, [3, 4, 5, 6, 7, 8, 9, 10], 1, hid, 0x90_000).unwrap();
        assert_eq!(words[1], ContextWord { offset: 4, value: 1 | (1 << 3) });
        assert_eq!(words[2], ContextWord { offset: 64, value: (3 << 27) | 3 });
        assert_eq!(words[10], ContextWord { offset: 192, value: 6 << 16 });
        assert_eq!(words[11], ContextWord { offset: 196, value: EP_ERROR_COUNT | EP_TYPE_INTERRUPT_IN | (8 << 16) });
    }
}
