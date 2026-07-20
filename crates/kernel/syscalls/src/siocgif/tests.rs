use super::*;

use alloc::sync::Arc;

#[test]
fn classifies_sioc_getters_and_mutators() {
    const UNKNOWN_SIOC: u64 = 0x89ff;
    for req in [
        SIOCGIFNAME, SIOCGIFCONF, SIOCGIFFLAGS, SIOCGIFADDR,
        SIOCGIFBRDADDR, SIOCGIFDSTADDR, SIOCGIFNETMASK, SIOCGIFMETRIC, SIOCGIFMTU, SIOCGIFHWADDR,
        SIOCGIFINDEX, SIOCGIFTXQLEN, SIOCGIFPFLAGS, SIOCGIFCOUNT, SIOCGIFSLAVE,
        SIOCSIFLINK, SIOCGIFMEM, SIOCSIFMEM, SIOCGIFENCAP, SIOCSIFENCAP,
        SIOCGIFMAP,
    ] { assert_eq!(sioc_access(req), Some(SiocAccess::Get)); }
    for req in [
        SIOCSIFFLAGS, SIOCSIFADDR, SIOCSIFBRDADDR, SIOCSIFDSTADDR, SIOCSIFNETMASK,
        SIOCSIFMETRIC, SIOCSIFNAME, SIOCSIFMTU, SIOCSIFHWADDR, SIOCSIFTXQLEN,
        SIOCSIFPFLAGS, SIOCADDRT, SIOCDELRT, SIOCSIFSLAVE, SIOCSIFMAP, SIOCSIFHWBROADCAST,
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

#[test]
fn unsupported_loopback_private_flags_getter_matches_setter() {
    const NS: u64 = 0x8440_0003;
    let stack = net::sock::stack();
    let iface = stack.ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), NS);
    let mut req = [0u8; IFREQ_SIZE];
    req[..2].copy_from_slice(b"lo");
    assert_eq!(siocgifpflags(NS, req.as_mut_ptr() as u64),
        -(Errno::Eopnotsupp.as_i32() as i64));
    let _ = stack.ifaces.unregister(iface);
}

#[test]
fn interface_metric_getter_returns_linux_default_zero() {
    const NS: u64 = 0x8440_0004;
    let stack = net::sock::stack();
    let iface = stack.ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), NS);
    let mut req = [0u8; IFREQ_SIZE];
    req[..2].copy_from_slice(b"lo");
    req[16..20].copy_from_slice(&i32::MAX.to_ne_bytes());
    assert_eq!(siocgifmetric(NS, req.as_mut_ptr() as u64), 0);
    assert_eq!(i32::from_ne_bytes(req[16..20].try_into().unwrap()), 0);
    let _ = stack.ifaces.unregister(iface);
}

#[test]
fn interface_metric_setter_matches_linux_errors() {
    const NS: u64 = 0x8440_0006;
    let stack = net::sock::stack();
    let iface = stack.ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), NS);
    let mut req = [0u8; IFREQ_SIZE];
    req[..2].copy_from_slice(b"lo");
    assert_eq!(siocsifmetric(NS, req.as_mut_ptr() as u64),
        -(Errno::Eopnotsupp.as_i32() as i64));
    req.fill(0);
    req[..7].copy_from_slice(b"missing");
    assert_eq!(siocsifmetric(NS, req.as_mut_ptr() as u64),
        -(Errno::Enodev.as_i32() as i64));
    let _ = stack.ifaces.unregister(iface);
    assert_eq!(siocsifmetric(NS, 0), -(Errno::Efault.as_i32() as i64));
}

#[test]
fn interface_count_getter_counts_only_live_namespace_devices() {
    const NS: u64 = 0x8440_0005;
    let stack = net::sock::stack();
    let before = stack.ifaces.snapshot_devs_in_ns(NS).len() as i32;
    let iface = stack.ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), NS);
    let mut req = [0u8; IFREQ_SIZE];
    assert_eq!(siocgifcount(NS, req.as_mut_ptr() as u64), 0);
    assert_eq!(i32::from_ne_bytes(req[16..20].try_into().unwrap()), before + 1);
    let _ = stack.ifaces.unregister(iface);
}

#[test]
fn interface_map_getter_returns_typed_device_map() {
    const NS: u64 = 0x8440_0006;
    let stack = net::sock::stack();
    let iface = stack.ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), NS);
    let mut req = [0xa5u8; IFREQ_SIZE];
    req[..2].copy_from_slice(b"lo");
    assert_eq!(siocgifmap(NS, req.as_mut_ptr() as u64), 0);
    assert_eq!(&req[16..40], &[0u8; 24]);
    req[..2].copy_from_slice(b"missing");
    assert_eq!(siocgifmap(NS, req.as_mut_ptr() as u64), -(Errno::Enodev.as_i32() as i64));
    let _ = stack.ifaces.unregister(iface);
    assert_eq!(handle_sioc_in(NS, SIOCGIFMAP, USER_VA_END),
        Some(-(Errno::Efault.as_i32() as i64)));
}
