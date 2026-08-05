use network_namespace::NetworkNamespaceRef;

use crate::net_ns::NetSysctlKey;

const FORWARDING: NetSysctlKey = NetSysctlKey::Ipv4Conf(
    crate::net_ns::Ipv4ConfDev::All, crate::net_ns::Ipv4ConfKey::Forwarding);
const IPV6_FORWARDING: NetSysctlKey = NetSysctlKey::Ipv6Forwarding;

/// `net.ipv4.ip_forward` for a retained namespace owner. # C: O(log N)
pub fn ipv4_enabled_for(namespace: &NetworkNamespaceRef) -> Option<bool> {
    crate::sysctl::value(namespace, FORWARDING).map(|value| value != 0)
}

/// Set `net.ipv4.ip_forward` for a retained namespace owner. # C: O(log N)
pub fn set_ipv4_enabled_for(namespace: &NetworkNamespaceRef, enabled: bool) -> Result<(), ()> {
    crate::sysctl::set_value(namespace, FORWARDING, i64::from(enabled))
}

/// `net.ipv4.ip_forward` for a live numeric namespace key. # C: O(log N)
pub fn ipv4_enabled_in(ns: u64) -> Option<bool> {
    crate::sysctl::value_in(ns, FORWARDING).map(|value| value != 0)
}

/// Set `net.ipv4.ip_forward` for a live numeric namespace key. # C: O(log N)
pub fn set_ipv4_enabled_in(ns: u64, enabled: bool) -> Result<(), ()> {
    crate::sysctl::set_value_in(ns, FORWARDING, i64::from(enabled))
}

/// `net.ipv6.conf.all.forwarding` for a retained namespace owner. # C: O(log N)
pub fn ipv6_enabled_for(namespace: &NetworkNamespaceRef) -> Option<bool> {
    crate::sysctl::value(namespace, IPV6_FORWARDING).map(|value| value != 0)
}

/// Set `net.ipv6.conf.all.forwarding` for a retained namespace owner. # C: O(log N)
pub fn set_ipv6_enabled_for(namespace: &NetworkNamespaceRef, enabled: bool) -> Result<(), ()> {
    crate::sysctl::set_value(namespace, IPV6_FORWARDING, i64::from(enabled))
}

/// `net.ipv6.conf.all.forwarding` for a live numeric namespace key. # C: O(log N)
pub fn ipv6_enabled_in(ns: u64) -> Option<bool> {
    crate::sysctl::value_in(ns, IPV6_FORWARDING).map(|value| value != 0)
}

/// Current task's `net.ipv4.ip_forward`. # C: O(log N)
pub fn ipv4_enabled() -> bool {
    let namespace = crate::net_ns::current_namespace();
    crate::net_ns::materialize_state(&namespace).sysctls.get(FORWARDING) != 0
}

/// Set current task's `net.ipv4.ip_forward`. # C: O(log N)
pub fn set_ipv4_enabled(enabled: bool) {
    let namespace = crate::net_ns::current_namespace();
    crate::net_ns::materialize_state(&namespace).sysctls.set(FORWARDING, i64::from(enabled));
}

/// Parse a Linux-style boolean sysctl write. # C: O(N)
pub fn parse_bool_sysctl(src: &[u8]) -> Option<bool> {
    let mut start = 0;
    let mut end = src.len();
    while start < end && src[start].is_ascii_whitespace() { start += 1; }
    while end > start && src[end - 1].is_ascii_whitespace() { end -= 1; }
    match &src[start..end] { b"0" => Some(false), b"1" => Some(true), _ => None }
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

    #[test]
    fn forwarding_is_isolated_per_owner() {
        let first = crate::net_ns::test_support::allocate_namespace();
        let second = crate::net_ns::test_support::allocate_namespace();
        crate::net_ns::materialize_state(&first);
        crate::net_ns::materialize_state(&second);
        set_ipv4_enabled_for(&first, true).unwrap();
        assert_eq!(ipv4_enabled_for(&first), Some(true));
        assert_eq!(ipv4_enabled_for(&second), Some(false));
    }

    #[test]
    fn ipv6_forwarding_is_independent_from_ipv4() {
        let namespace = crate::net_ns::test_support::allocate_namespace();
        crate::net_ns::materialize_state(&namespace);
        set_ipv4_enabled_for(&namespace, true).unwrap();
        assert_eq!(ipv6_enabled_for(&namespace), Some(false));
        set_ipv6_enabled_for(&namespace, true).unwrap();
        assert_eq!(ipv4_enabled_for(&namespace), Some(true));
    }
}
