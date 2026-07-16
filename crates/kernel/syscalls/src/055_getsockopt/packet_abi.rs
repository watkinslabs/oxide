/// Validate and cap a Linux packet integer getsockopt length. # C: O(1)
pub(super) fn packet_i32_copy_len(requested: i32) -> Option<usize> {
    if requested < 0 { return None; }
    Some(core::cmp::min(requested as usize, core::mem::size_of::<i32>()))
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
}
