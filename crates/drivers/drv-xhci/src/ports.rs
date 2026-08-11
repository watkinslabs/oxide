//! Root-hub port-status event decoding and PORTSC acknowledgement.

/// First operational port-register block. # C: O(1)
pub const PORTSC_BASE: u64 = 0x400;
/// Bytes between xHCI port-register blocks. # C: O(1)
pub const PORT_STRIDE: u64 = 0x10;
/// PORTSC connection status. # C: O(1)
pub const PORT_CONNECT: u32 = 1;
/// PORTSC enabled status. # C: O(1)
pub const PORT_ENABLED: u32 = 1 << 1;
/// PORTSC device-speed field. # C: O(1)
pub const PORT_SPEED_MASK: u32 = 0xf << 10;
/// PORTSC write-one-to-clear change bits, matching Linux `PORT_CHANGE_MASK`. # C: O(1)
pub const PORT_CHANGE_MASK: u32 = (1 << 17) | (1 << 18) | (1 << 19) | (1 << 20) | (1 << 21) | (1 << 22) | (1 << 23);
/// Port Status Change Event TRB type. # C: O(1)
pub const TRB_PORT_STATUS: u32 = 34;

/// Decode the physical port ID from a valid port-status event TRB. # C: O(1)
pub fn event_port_id(parameter: u32, control: u32, max_ports: u8) -> Option<u8> {
    let kind = (control >> crate::ring::TRB_TYPE_SHIFT) & 0x3f;
    let port = (parameter >> 24) as u8;
    (kind == TRB_PORT_STATUS && port != 0 && port <= max_ports).then_some(port)
}

/// Validated PORTSC offset for one one-based physical port number. # C: O(1)
pub fn portsc_offset(operational: u64, port: u8, max_ports: u8) -> Option<u64> {
    if port == 0 || port > max_ports { return None; }
    operational.checked_add(PORTSC_BASE)?.checked_add((port as u64 - 1).checked_mul(PORT_STRIDE)?)
}

/// Isolate the only PORTSC bits software may acknowledge with ones. # C: O(1)
pub fn acknowledge_changes(portsc: u32) -> u32 { portsc & PORT_CHANGE_MASK }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_event_requires_a_real_in_range_port() {
        let control = TRB_PORT_STATUS << crate::ring::TRB_TYPE_SHIFT;
        assert_eq!(event_port_id(3 << 24, control, 8), Some(3));
        assert_eq!(event_port_id(0, control, 8), None);
        assert_eq!(event_port_id(9 << 24, control, 8), None);
        assert_eq!(event_port_id(3 << 24, 0, 8), None);
    }

    #[test]
    fn port_ack_only_contains_w1c_change_bits() {
        let portsc = PORT_CONNECT | PORT_ENABLED | PORT_SPEED_MASK | (1 << 17) | (1 << 21);
        assert_eq!(acknowledge_changes(portsc), (1 << 17) | (1 << 21));
        assert_eq!(portsc_offset(0x40, 1, 8), Some(0x440));
        assert_eq!(portsc_offset(0x40, 8, 8), Some(0x4b0));
        assert_eq!(portsc_offset(0x40, 0, 8), None);
    }
}
