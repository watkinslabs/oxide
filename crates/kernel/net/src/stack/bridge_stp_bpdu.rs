//! IEEE 802.1D configuration BPDU codec for the canonical bridge owner.

const BPDU_CONFIG_LEN: usize = 35;
const BPDU_PROTOCOL_ID_END: usize = 2;
const BPDU_VERSION_OFFSET: usize = 2;
const BPDU_TYPE_OFFSET: usize = 3;
const BPDU_FLAGS_OFFSET: usize = 4;
const BPDU_ROOT_ID_OFFSET: usize = 5;
const BPDU_ROOT_COST_OFFSET: usize = 13;
const BPDU_BRIDGE_ID_OFFSET: usize = 17;
const BPDU_PORT_ID_OFFSET: usize = 25;
const BPDU_MESSAGE_AGE_OFFSET: usize = 27;
const BPDU_MAX_AGE_OFFSET: usize = 29;
const BPDU_HELLO_TIME_OFFSET: usize = 31;
const BPDU_FORWARD_DELAY_OFFSET: usize = 33;
const BPDU_CONFIG_TYPE: u8 = 0;
const BPDU_VERSION: u8 = 0;
const STP_TICKS_PER_SEC: u64 = 256;
const BRIDGE_CLOCK_TICKS_PER_SEC: u64 = 100;
const TOPOLOGY_CHANGE: u8 = 1;
const TOPOLOGY_CHANGE_ACK: u8 = 1 << 7;

/// Parsed IEEE 802.1D Configuration BPDU, after its LLC header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StpConfigBpdu {
    pub(crate) topology_change: bool,
    pub(crate) topology_change_ack: bool,
    pub(crate) root_id: [u8; 8],
    pub(crate) root_path_cost: u32,
    pub(crate) bridge_id: [u8; 8],
    pub(crate) port_id: u16,
    pub(crate) message_age: u64,
    pub(crate) max_age: u64,
    pub(crate) hello_time: u64,
    pub(crate) forward_delay: u64,
}

impl StpConfigBpdu {
    /// Decode Linux's version-zero 35-byte Configuration BPDU payload. # C: O(1)
    pub(crate) fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < BPDU_CONFIG_LEN || bytes[..BPDU_PROTOCOL_ID_END] != [0, 0]
            || bytes[BPDU_VERSION_OFFSET] != BPDU_VERSION || bytes[BPDU_TYPE_OFFSET] != BPDU_CONFIG_TYPE
        { return None; }
        let flags = bytes[BPDU_FLAGS_OFFSET];
        let mut root_id = [0; 8]; root_id.copy_from_slice(&bytes[BPDU_ROOT_ID_OFFSET..BPDU_ROOT_COST_OFFSET]);
        let mut bridge_id = [0; 8]; bridge_id.copy_from_slice(&bytes[BPDU_BRIDGE_ID_OFFSET..BPDU_PORT_ID_OFFSET]);
        Some(Self { topology_change: flags & TOPOLOGY_CHANGE != 0,
            topology_change_ack: flags & TOPOLOGY_CHANGE_ACK != 0, root_id,
            root_path_cost: u32::from_be_bytes(bytes[BPDU_ROOT_COST_OFFSET..BPDU_BRIDGE_ID_OFFSET].try_into().ok()?),
            bridge_id, port_id: u16::from_be_bytes(bytes[BPDU_PORT_ID_OFFSET..BPDU_MESSAGE_AGE_OFFSET].try_into().ok()?),
            message_age: from_stp_ticks(u16::from_be_bytes(bytes[BPDU_MESSAGE_AGE_OFFSET..BPDU_MAX_AGE_OFFSET].try_into().ok()?)),
            max_age: from_stp_ticks(u16::from_be_bytes(bytes[BPDU_MAX_AGE_OFFSET..BPDU_HELLO_TIME_OFFSET].try_into().ok()?)),
            hello_time: from_stp_ticks(u16::from_be_bytes(bytes[BPDU_HELLO_TIME_OFFSET..BPDU_FORWARD_DELAY_OFFSET].try_into().ok()?)),
            forward_delay: from_stp_ticks(u16::from_be_bytes(bytes[BPDU_FORWARD_DELAY_OFFSET..BPDU_CONFIG_LEN].try_into().ok()?)), })
    }

    /// Encode Linux's version-zero 35-byte Configuration BPDU payload. # C: O(1)
    pub(crate) fn encode(&self) -> [u8; BPDU_CONFIG_LEN] {
        let mut bytes = [0; BPDU_CONFIG_LEN];
        bytes[BPDU_TYPE_OFFSET] = BPDU_CONFIG_TYPE;
        bytes[BPDU_FLAGS_OFFSET] = u8::from(self.topology_change) * TOPOLOGY_CHANGE
            | u8::from(self.topology_change_ack) * TOPOLOGY_CHANGE_ACK;
        bytes[BPDU_ROOT_ID_OFFSET..BPDU_ROOT_COST_OFFSET].copy_from_slice(&self.root_id);
        bytes[BPDU_ROOT_COST_OFFSET..BPDU_BRIDGE_ID_OFFSET].copy_from_slice(&self.root_path_cost.to_be_bytes());
        bytes[BPDU_BRIDGE_ID_OFFSET..BPDU_PORT_ID_OFFSET].copy_from_slice(&self.bridge_id);
        bytes[BPDU_PORT_ID_OFFSET..BPDU_MESSAGE_AGE_OFFSET].copy_from_slice(&self.port_id.to_be_bytes());
        bytes[BPDU_MESSAGE_AGE_OFFSET..BPDU_MAX_AGE_OFFSET].copy_from_slice(&to_stp_ticks(self.message_age).to_be_bytes());
        bytes[BPDU_MAX_AGE_OFFSET..BPDU_HELLO_TIME_OFFSET].copy_from_slice(&to_stp_ticks(self.max_age).to_be_bytes());
        bytes[BPDU_HELLO_TIME_OFFSET..BPDU_FORWARD_DELAY_OFFSET].copy_from_slice(&to_stp_ticks(self.hello_time).to_be_bytes());
        bytes[BPDU_FORWARD_DELAY_OFFSET..BPDU_CONFIG_LEN].copy_from_slice(&to_stp_ticks(self.forward_delay).to_be_bytes());
        bytes
    }
}

fn to_stp_ticks(ticks: u64) -> u16 {
    core::cmp::min(ticks.saturating_mul(STP_TICKS_PER_SEC) / BRIDGE_CLOCK_TICKS_PER_SEC,
        u16::MAX as u64) as u16
}

fn from_stp_ticks(ticks: u16) -> u64 {
    (ticks as u64).saturating_mul(BRIDGE_CLOCK_TICKS_PER_SEC)
        .saturating_add(STP_TICKS_PER_SEC - 1) / STP_TICKS_PER_SEC
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_bpdu_uses_linux_offsets_and_stp_tick_conversion() {
        let input = StpConfigBpdu { topology_change: true, topology_change_ack: true,
            root_id: [0x80, 0, 1, 2, 3, 4, 5, 6], root_path_cost: 19,
            bridge_id: [0x80, 0, 6, 5, 4, 3, 2, 1], port_id: 0x8001,
            message_age: 100, max_age: 2_000, hello_time: 200, forward_delay: 1_500 };
        let bytes = input.encode();
        assert_eq!(bytes[BPDU_FLAGS_OFFSET], TOPOLOGY_CHANGE | TOPOLOGY_CHANGE_ACK);
        assert_eq!(bytes[BPDU_ROOT_COST_OFFSET..BPDU_BRIDGE_ID_OFFSET], 19u32.to_be_bytes());
        assert_eq!(bytes[BPDU_PORT_ID_OFFSET..BPDU_MESSAGE_AGE_OFFSET], 0x8001u16.to_be_bytes());
        assert_eq!(bytes[BPDU_HELLO_TIME_OFFSET..BPDU_FORWARD_DELAY_OFFSET], 512u16.to_be_bytes());
        assert_eq!(StpConfigBpdu::parse(&bytes), Some(input));
    }

    #[test]
    fn config_bpdu_rejects_non_configuration_versions_and_short_payloads() {
        assert_eq!(StpConfigBpdu::parse(&[0; BPDU_CONFIG_LEN - 1]), None);
        let mut bad = [0; BPDU_CONFIG_LEN]; bad[BPDU_VERSION_OFFSET] = 2;
        assert_eq!(StpConfigBpdu::parse(&bad), None);
    }
}
