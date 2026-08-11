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

/// Build the Input Control, Slot, and endpoint-zero contexts for Address Device.
/// `bytes` must be a controller-owned, zeroed input-context region. # C: O(1)
pub fn address_device(bytes: &mut [u8], context_bytes: u8, port: u8, portsc: u32, ep0_ring_pa: u64) -> bool {
    let stride = context_bytes as usize;
    if !matches!(stride, 32 | 64) || port == 0 || ep0_ring_pa & 0xf != 0 || bytes.len() < (EP0_CONTEXT + 1) * stride { return false; }
    let speed = (portsc & crate::ports::PORT_SPEED_MASK) >> 10;
    let max_packet = match speed { 1 => 64, 2 => 8, 3 => 64, 4 | 5 => 512, _ => return false };
    let icc = INPUT_CONTROL_CONTEXT * stride;
    let slot = SLOT_CONTEXT * stride;
    let ep0 = EP0_CONTEXT * stride;
    // xHCI context fields are little-endian; supported controller targets are LE.
    put32(bytes, icc + 4, ADD_SLOT_AND_EP0);
    put32(bytes, slot, SLOT_LAST_CONTEXT_EP0 | (speed << SLOT_SPEED_SHIFT));
    put32(bytes, slot + 4, (port as u32) << SLOT_ROOT_HUB_PORT_SHIFT);
    put32(bytes, ep0 + 4, EP0_TYPE_CONTROL | EP0_ERROR_COUNT | (max_packet << 16));
    put64(bytes, ep0 + 8, ep0_ring_pa | EP0_DEQUEUE_CYCLE);
    put32(bytes, ep0 + 16, EP0_AVERAGE_TRB);
    true
}

fn put32(bytes: &mut [u8], offset: usize, value: u32) { bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes()); }
fn put64(bytes: &mut [u8], offset: usize, value: u64) { bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes()); }

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
}
