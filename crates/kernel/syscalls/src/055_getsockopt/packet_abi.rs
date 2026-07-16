/// Validate and cap a Linux packet integer getsockopt length. # C: O(1)
pub(super) fn packet_i32_copy_len(requested: i32) -> Option<usize> {
    if requested < 0 { return None; }
    Some(core::cmp::min(requested as usize, core::mem::size_of::<i32>()))
}

/// Encode Linux V1/V2 or V3 packet statistics layout. # C: O(1)
pub(super) fn packet_statistics_bytes(version: u8, statistics: net::sock::PacketStatistics)
    -> ([u8; 12], usize)
{
    let mut value = [0u8; 12];
    value[0..4].copy_from_slice(&statistics.packets.to_ne_bytes());
    value[4..8].copy_from_slice(&statistics.drops.to_ne_bytes());
    value[8..12].copy_from_slice(&statistics.freeze_queue_count.to_ne_bytes());
    let len = if version == net::uapi::TPACKET_V3 { value.len() } else { 8 };
    (value, len)
}

/// Encode native Linux `struct tpacket_rollover_stats`. # C: O(1)
pub(super) fn packet_rollover_statistics_bytes(statistics: net::sock::PacketRolloverStatistics)
    -> [u8; 24]
{
    let mut value = [0u8; 24];
    value[0..8].copy_from_slice(&statistics.all.to_ne_bytes());
    value[8..16].copy_from_slice(&statistics.huge.to_ne_bytes());
    value[16..24].copy_from_slice(&statistics.failed.to_ne_bytes());
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_i32_get_uses_linux_value_result_length() {
        assert_eq!(packet_i32_copy_len(-1), None);
        assert_eq!(packet_i32_copy_len(0), Some(0));
        assert_eq!(packet_i32_copy_len(1), Some(1));
        assert_eq!(packet_i32_copy_len(4), Some(4));
        assert_eq!(packet_i32_copy_len(64), Some(4));
    }

    #[test]
    fn packet_statistics_layout_depends_only_on_tpacket_version() {
        let statistics = net::sock::PacketStatistics {
            packets: 9, drops: 3, freeze_queue_count: 2,
        };
        let (v1, v1_len) = packet_statistics_bytes(net::uapi::TPACKET_V1, statistics);
        assert_eq!(v1_len, 8);
        assert_eq!(u32::from_ne_bytes(v1[0..4].try_into().unwrap()), 9);
        assert_eq!(u32::from_ne_bytes(v1[4..8].try_into().unwrap()), 3);
        let (v3, v3_len) = packet_statistics_bytes(net::uapi::TPACKET_V3, statistics);
        assert_eq!(v3_len, 12);
        assert_eq!(u32::from_ne_bytes(v3[8..12].try_into().unwrap()), 2);
    }

    #[test]
    fn rollover_statistics_use_three_native_u64_fields() {
        let value = packet_rollover_statistics_bytes(net::sock::PacketRolloverStatistics {
            all: 7, huge: 5, failed: 3,
        });
        assert_eq!(u64::from_ne_bytes(value[0..8].try_into().unwrap()), 7);
        assert_eq!(u64::from_ne_bytes(value[8..16].try_into().unwrap()), 5);
        assert_eq!(u64::from_ne_bytes(value[16..24].try_into().unwrap()), 3);
    }
}
