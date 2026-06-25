use core::sync::atomic::{AtomicBool, Ordering};

static IPV4_FORWARDING: AtomicBool = AtomicBool::new(false);

/// Current `net.ipv4.ip_forward` value. # C: O(1)
pub fn ipv4_enabled() -> bool {
    IPV4_FORWARDING.load(Ordering::Acquire)
}

/// Set `net.ipv4.ip_forward`. # C: O(1)
pub fn set_ipv4_enabled(enabled: bool) {
    IPV4_FORWARDING.store(enabled, Ordering::Release);
}

/// Parse a Linux-style boolean sysctl write. # C: O(N)
pub fn parse_bool_sysctl(src: &[u8]) -> Option<bool> {
    let mut start = 0;
    let mut end = src.len();
    while start < end && src[start].is_ascii_whitespace() { start += 1; }
    while end > start && src[end - 1].is_ascii_whitespace() { end -= 1; }
    match &src[start..end] {
        b"0" => Some(false),
        b"1" => Some(true),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bool_sysctl_accepts_linux_values() {
        assert_eq!(parse_bool_sysctl(b"0\n"), Some(false));
        assert_eq!(parse_bool_sysctl(b"1"), Some(true));
        assert_eq!(parse_bool_sysctl(b" 1\t\n"), Some(true));
        assert_eq!(parse_bool_sysctl(b"2\n"), None);
    }
}
