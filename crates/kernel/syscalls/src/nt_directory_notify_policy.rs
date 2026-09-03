//! Host-testable policy and record layout for native directory notifications.

pub const FILE_NOTIFY_CHANGE_FILE_NAME: u32 = 0x0001;
pub const FILE_NOTIFY_CHANGE_DIR_NAME: u32 = 0x0002;
pub const FILE_NOTIFY_ALL: u32 = FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME;

pub const fn valid_filter(filter: u32) -> bool {
    filter != 0 && filter & !FILE_NOTIFY_ALL == 0
}

pub fn record_size(leaf: &str) -> usize {
    (12 + leaf.encode_utf16().count() * 2 + 3) & !3
}

pub fn encode_record(leaf: &str, action: u32, out: &mut [u8]) -> Option<usize> {
    let size = record_size(leaf);
    if out.len() < size { return None; }
    out[..size].fill(0);
    out[4..8].copy_from_slice(&action.to_le_bytes());
    let name_len = (leaf.encode_utf16().count() * 2) as u32;
    out[8..12].copy_from_slice(&name_len.to_le_bytes());
    for (index, unit) in leaf.encode_utf16().enumerate() {
        out[12 + index * 2..14 + index * 2].copy_from_slice(&unit.to_le_bytes());
    }
    Some(size)
}

#[cfg(test)]
mod tests {
    use super::{encode_record, record_size, valid_filter, FILE_NOTIFY_ALL};

    #[test]
    fn filters_require_a_supported_name_class() {
        assert!(!valid_filter(0));
        assert!(valid_filter(FILE_NOTIFY_ALL));
        assert!(!valid_filter(0x100));
    }

    #[test]
    fn records_are_aligned_and_report_utf16_byte_length() {
        let mut out = [0u8; 32];
        let size = encode_record("é", 1, &mut out).unwrap();
        assert_eq!(size, record_size("é"));
        assert_eq!(size % 4, 0);
        assert_eq!(&out[4..8], &1u32.to_le_bytes());
        assert_eq!(&out[8..12], &2u32.to_le_bytes());
        assert_eq!(&out[12..14], &0x00e9u16.to_le_bytes());
    }

    #[test]
    fn short_output_is_rejected() {
        let mut out = [0u8; 15];
        assert!(encode_record("file", 2, &mut out).is_none());
    }
}
