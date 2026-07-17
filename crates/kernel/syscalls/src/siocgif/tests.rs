use super::*;

use alloc::sync::Arc;

#[test]
fn classifies_sioc_getters_and_mutators() {
    const UNKNOWN_SIOC: u64 = 0x89ff;
    for req in [
        SIOCGIFNAME, SIOCGIFCONF, SIOCGIFFLAGS, SIOCGIFADDR,
        SIOCGIFBRDADDR, SIOCGIFNETMASK, SIOCGIFMTU, SIOCGIFHWADDR,
        SIOCGIFINDEX, SIOCGIFTXQLEN, SIOCGIFPFLAGS,
    ] { assert_eq!(sioc_access(req), Some(SiocAccess::Get)); }
    for req in [
        SIOCSIFFLAGS, SIOCSIFADDR, SIOCSIFBRDADDR, SIOCSIFNETMASK,
        SIOCSIFMTU, SIOCSIFHWADDR, SIOCSIFTXQLEN, SIOCSIFPFLAGS, SIOCADDRT, SIOCDELRT,
    ] { assert_eq!(sioc_access(req), Some(SiocAccess::Mutate)); }
    assert_eq!(sioc_access(UNKNOWN_SIOC), None);
}

#[test]
fn ipv4_getters_distinguish_missing_iface_from_missing_address() {
    const NS: u64 = 0x8440_0001;
    assert!(matches!(lookup_ipv4_getter(NS, "missing844"), Err(Errno::Enodev)));
    let stack = net::sock::stack();
    let iface = stack.ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), NS);
    assert!(matches!(lookup_ipv4_getter(NS, "lo"), Err(Errno::Eaddrnotavail)));
    let _ = stack.ifaces.unregister(iface);
}

#[test]
fn user_ranges_reject_overflow_and_crossing_user_end() {
    assert!(!user_range(0, IFREQ_SIZE));
    assert!(!user_range(u64::MAX - 7, IFREQ_SIZE));
    assert!(!user_range(USER_VA_END - IFREQ_SIZE as u64 + 1, IFREQ_SIZE));
    assert!(user_range(USER_VA_END - IFREQ_SIZE as u64, IFREQ_SIZE));
    assert!(!user_range(USER_VA_END - IFCONF_SIZE as u64 + 1, IFCONF_SIZE));
}

#[test]
fn ifreq_uses_native_pointer_union_size() {
    assert_eq!(IFREQ_SIZE, 40);
    assert_eq!(IFREQ_SIZE - IFNAMSIZ - 16, 8);
}

#[test]
fn ifname_missing_index_is_enodev_and_loopback_reports_loopback_type() {
    const NS: u64 = 0x8440_0002;
    let mut req = [0u8; IFREQ_SIZE];
    req[16..20].copy_from_slice(&i32::MAX.to_ne_bytes());
    assert_eq!(siocgifname(NS, req.as_mut_ptr() as u64), -(Errno::Enodev.as_i32() as i64));

    let stack = net::sock::stack();
    let iface = stack.ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), NS);
    req.fill(0);
    req[..2].copy_from_slice(b"lo");
    assert_eq!(siocgifhwaddr(NS, req.as_mut_ptr() as u64), 0);
    assert_eq!(u16::from_ne_bytes([req[16], req[17]]), ARPHRD_LOOPBACK);
    let _ = stack.ifaces.unregister(iface);
    assert!(matches!(live_iface_flags(iface), Err(Errno::Enodev)));
}
