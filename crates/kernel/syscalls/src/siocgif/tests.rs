// PHANTOM until the module above loses its target gate.
//
// This file is declared by `siocgif.rs`, which is
// `#![cfg(target_os = "oxide-kernel")]`, and a `#[cfg(test)]` module inherits
// that gate: none of what follows compiles under `cargo test`, so it reports
// as neither run nor skipped. B2043 moved the parts that are pure decisions --
// the command table, the ABI sizes, the user-range check -- into the ungated
// `siocgif_decide`, where their cases now run and were each shown able to fail.
//
// What is left here needs two things a hosted build does not have: user memory
// reachable through a raw address (`handle_sioc_in`, `siocgifname` and the
// other entry points take a `u64` the shim copies through the exception
// table), and `net::sock::stack()` reached from the kernel's own namespace
// wiring. Closing the gap means giving each entry point an inner form that
// takes an already-copied `[u8; IFREQ_SIZE]` and returns the bytes to copy
// back, leaving the gated function as the copy in, call, copy out -- the
// shape `docs/53` asks for. Until that happens these cases are documentation.

use super::*;
use hal::USER_VA_END;

// The command table, the ABI sizes and the user-range check moved to
// `crate::siocgif_decide`, which is ungated: their cases run there instead of
// being compiled out here.

use alloc::sync::Arc;


#[test]
fn legacy_rarp_imports_ifreq_before_terminal_enotty() {
    let mut ifreq = [0u8; IFREQ_SIZE];
    for command in [SIOCDRARP, SIOCGRARP, SIOCSRARP] {
        assert_eq!(handle_sioc_in(0, command, ifreq.as_mut_ptr() as u64),
            Some(-(Errno::Enotty.as_i32() as i64)));
        assert_eq!(handle_sioc_in(0, command, USER_VA_END),
            Some(-(Errno::Efault.as_i32() as i64)));
    }
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
fn ifname_missing_index_is_enodev_and_loopback_reports_loopback_type() {
    const NS: u64 = 0x8440_0002;
    let mut req = [0u8; IFREQ_SIZE];
    req[16..20].copy_from_slice(&i32::MAX.to_ne_bytes());
    assert_eq!(siocgifname_inner(NS, &mut req), -(Errno::Enodev.as_i32() as i64));

    let stack = net::sock::stack();
    let iface = stack.ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), NS);
    req.fill(0);
    req[..2].copy_from_slice(b"lo");
    assert_eq!(siocgifhwaddr_inner(NS, &mut req), 0);
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
    assert_eq!(siocgifpflags_inner(NS, &mut req),
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
    assert_eq!(siocgifmetric_inner(NS, &mut req), 0);
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
    assert_eq!(siocsifmetric_inner(NS, &mut req),
        -(Errno::Eopnotsupp.as_i32() as i64));
    req.fill(0);
    req[..7].copy_from_slice(b"missing");
    assert_eq!(siocsifmetric(NS, req.as_mut_ptr() as u64),
        -(Errno::Enodev.as_i32() as i64));
    let _ = stack.ifaces.unregister(iface);
    assert_eq!(sioc_access(SIOCGIFMETRIC, 0), Ok(Some(SiocAccess::Get)));
}

#[test]
fn interface_count_getter_counts_only_live_namespace_devices() {
    const NS: u64 = 0x8440_0005;
    let stack = net::sock::stack();
    let before = stack.ifaces.snapshot_devs_in_ns(NS).len() as i32;
    let iface = stack.ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), NS);
    let mut req = [0u8; IFREQ_SIZE];
    assert_eq!(siocgifcount_inner(NS, &mut req), 0);
    assert_eq!(i32::from_ne_bytes(req[16..20].try_into().unwrap()), before + 1);
    let _ = stack.ifaces.unregister(iface);
}

#[test]
fn interface_map_getter_returns_typed_device_map() {
    const NS: u64 = 0x8440_0006;
    let stack = net::sock::stack();
    let iface = stack.ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), NS);
    let mut req = [0xa5u8; IFREQ_SIZE];
    req[..IFNAMSIZ].fill(0);
    req[..2].copy_from_slice(b"lo");
    assert_eq!(siocgifmap_inner(NS, &mut req), 0);
    assert_eq!(&req[16..40], &[0u8; 24]);
    req[..7].copy_from_slice(b"missing");
    assert_eq!(siocgifmap_inner(NS, &mut req), -(Errno::Enodev.as_i32() as i64));
    let _ = stack.ifaces.unregister(iface);
    assert_eq!(user_range(USER_VA_END, IFREQ_SIZE), false);
}

#[test]
fn ethtool_is_a_getter_and_answers_glink_from_the_running_flag() {
    const NS: u64 = 0x8446_0001;
    // Classified as a read, never a mutator: SIOCETHTOOL's bounded command set
    // only reports state, so a read-only socket fd must be allowed to issue it.
    assert_eq!(sioc_access(ethtool::SIOCETHTOOL, 0), Ok(Some(SiocAccess::Get)));
    // Carrier is the same IFF_RUNNING bit SIOCGIFFLAGS reports, so GLINK and the
    // flags ioctl cannot disagree. Loopback registers with carrier present.
    let stack = net::sock::stack();
    let iface = stack.ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), NS);
    let (id, _) = stack.ifaces.lookup_name_in_ns("lo", NS).expect("registered lo");
    let flags = live_iface_flags(id).expect("live flags");
    assert_ne!(u32::from(flags) & net::netdev::iff::IFF_RUNNING, 0,
        "loopback must report carrier, else GLINK would answer link-down");
    let _ = stack.ifaces.unregister(iface);
}
