// Event-type numbers and the fixed geometry of a first-format record.

/// Fixed-format record header: register u32, type u32, digest, size u32.
pub const TCG_EVENT1_HEADER_LEN: usize = 32;
/// Digest carried by a fixed-format record.
pub const TCG_EVENT1_DIGEST_LEN: usize = 20;
/// Crypto-agile record header up to the digest count: register, type, count.
pub const TCG_EVENT2_PREFIX_LEN: usize = 12;

pub const EV_PREBOOT: u32 = 0;
pub const EV_POST_CODE: u32 = 1;
pub const EV_UNUSED: u32 = 2;
pub const EV_NO_ACTION: u32 = 3;
pub const EV_SEPARATOR: u32 = 4;
pub const EV_ACTION: u32 = 5;
pub const EV_EVENT_TAG: u32 = 6;
pub const EV_SCRTM_CONTENTS: u32 = 7;
pub const EV_SCRTM_VERSION: u32 = 8;
pub const EV_CPU_MICROCODE: u32 = 9;
pub const EV_PLATFORM_CONFIG_FLAGS: u32 = 10;
pub const EV_TABLE_OF_DEVICES: u32 = 11;
pub const EV_COMPACT_HASH: u32 = 12;
pub const EV_IPL: u32 = 13;
pub const EV_IPL_PARTITION_DATA: u32 = 14;
pub const EV_NONHOST_CODE: u32 = 15;
pub const EV_NONHOST_CONFIG: u32 = 16;
pub const EV_NONHOST_INFO: u32 = 17;

/// Name of an event type, or `None` when unassigned. # C: O(1)
pub fn event_type_name(t: u32) -> Option<&'static str> {
    Some(match t {
        EV_PREBOOT => "PREBOOT",
        EV_POST_CODE => "POST CODE",
        EV_NO_ACTION => "NO ACTION",
        EV_SEPARATOR => "SEPARATOR",
        EV_ACTION => "ACTION",
        EV_EVENT_TAG => "EVENT TAG",
        EV_SCRTM_CONTENTS => "S-CRTM Contents",
        EV_SCRTM_VERSION => "S-CRTM Version",
        EV_CPU_MICROCODE => "CPU Microcode",
        EV_PLATFORM_CONFIG_FLAGS => "Platform Config Flags",
        EV_TABLE_OF_DEVICES => "Table of Devices",
        EV_COMPACT_HASH => "Compact Hash",
        EV_IPL => "IPL",
        EV_IPL_PARTITION_DATA => "IPL Partition Data",
        EV_NONHOST_CODE => "Non-Host Code",
        EV_NONHOST_CONFIG => "Non-Host Config",
        EV_NONHOST_INFO => "Non-Host Info",
        _ => return None,
    })
}
