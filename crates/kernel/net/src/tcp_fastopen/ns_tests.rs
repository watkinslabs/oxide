use super::*;
use super::super::flags::{TFO_DEFAULT, TFO_SERVER_ENABLE};

fn namespace() -> NetworkNamespaceRef {
    let namespace = crate::net_ns::test_support::allocate_namespace();
    crate::net_ns::materialize_state(&namespace);
    namespace
}

#[test]
fn a_fresh_namespace_reports_the_compiled_enable_bits() {
    let ns = namespace();
    assert_eq!(enable_bits(&ns), TFO_DEFAULT);
    assert_eq!(enable_bits_in(ns.id().as_u64()), Some(TFO_DEFAULT));
}

#[test]
fn the_enable_bits_are_isolated_per_namespace() {
    let first = namespace();
    let second = namespace();
    crate::sysctl::set_value(&first, NetSysctlKey::TcpFastopen,
        (TFO_DEFAULT | TFO_SERVER_ENABLE) as i64).unwrap();
    assert_eq!(enable_bits(&first), TFO_DEFAULT | TFO_SERVER_ENABLE);
    assert_eq!(enable_bits(&second), TFO_DEFAULT);
}

#[test]
fn an_invented_namespace_id_reports_no_bits_and_creates_no_state() {
    assert_eq!(enable_bits_in(u64::MAX), None);
}

#[test]
fn keys_are_drawn_once_and_never_redrawn() {
    let ns = namespace();
    assert_eq!(ns_keys(&ns), None);
    init_key_once(&ns);
    let first = ns_keys(&ns).expect("a drawn key");
    init_key_once(&ns);
    assert_eq!(ns_keys(&ns), Some(first));
    // The draw names one key, not a pair: there is nothing to keep a backup
    // of until an administrator rotates.
    assert_eq!(first.backup, None);
}

#[test]
fn keys_are_isolated_per_namespace() {
    let first = namespace();
    let second = namespace();
    init_key_once(&first);
    assert!(ns_keys(&first).is_some());
    assert_eq!(ns_keys(&second), None);
    init_key_once(&second);
    // Two namespaces must not share a cookie key; a cookie minted in one is
    // then meaningless in the other.
    assert_ne!(ns_keys(&first), ns_keys(&second));
}

#[test]
fn an_administrative_write_replaces_the_drawn_keys() {
    let ns = namespace();
    init_key_once(&ns);
    let drawn = ns_keys(&ns).unwrap();
    let installed = KeyCtx::new(Key::new([0x5a; KEY_LEN]), Some(Key::new([0x1c; KEY_LEN])));
    set_ns_keys(&ns, installed);
    assert_eq!(ns_keys(&ns), Some(installed));
    assert_ne!(ns_keys(&ns), Some(drawn));
    // And a later lazy draw does not undo it.
    init_key_once(&ns);
    assert_eq!(ns_keys(&ns), Some(installed));
}

#[test]
fn the_blackhole_timeout_starts_off_and_the_pause_with_it() {
    let ns = namespace();
    assert_eq!(blackhole_timeout(&ns), super::super::flags::BLACKHOLE_TIMEOUT_DEFAULT);
    blackhole_disable(&ns, 1_000);
    assert_eq!(blackhole_times(&ns), 0, "a zero timeout records nothing");
    assert_eq!(blackhole_pause(&ns, 1_000), super::super::blackhole::Pause::Off);
}

#[test]
fn a_configured_timeout_makes_a_detection_pause_the_namespace() {
    let ns = namespace();
    crate::sysctl::set_value(&ns,
        crate::net_ns::NetSysctlKey::TcpFastopenBlackholeTimeout, 60).expect("the write");
    assert_eq!(blackhole_timeout(&ns), 60);
    blackhole_disable(&ns, 0);
    assert_eq!(blackhole_pause(&ns, 30 * 1_000_000_000), super::super::blackhole::Pause::Held);
    assert_eq!(blackhole_pause(&ns, 61 * 1_000_000_000), super::super::blackhole::Pause::Expired);
    blackhole_reset(&ns);
    assert_eq!(blackhole_pause(&ns, 30 * 1_000_000_000), super::super::blackhole::Pause::Off);
}

#[test]
fn the_pause_is_isolated_per_namespace() {
    let first = namespace();
    let second = namespace();
    for ns in [&first, &second] {
        crate::sysctl::set_value(ns,
            crate::net_ns::NetSysctlKey::TcpFastopenBlackholeTimeout, 60).expect("the write");
    }
    blackhole_disable(&first, 0);
    assert_eq!(blackhole_pause(&first, 0), super::super::blackhole::Pause::Held);
    assert_eq!(blackhole_pause(&second, 0), super::super::blackhole::Pause::Off);
}

#[test]
fn a_cookie_learned_in_one_namespace_is_not_visible_in_another() {
    use crate::addr::{IpAddr, Ipv4Addr};
    let first = namespace();
    let second = namespace();
    let src = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5));
    let dst = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
    let learned = super::super::learn::Learned {
        cookie: Some(crate::tcp_conn::fastopen::Cookie::minted([3; 8], false)),
        syn_lost: false, try_exp: 0, failed: false, data_acked: true,
        client_fail: super::super::client::TFO_STATUS_NONE,
    };
    cache_learned(&first, src, dst, 1_000, 1460, &learned);
    assert_eq!(cached_cookie(&first, src, dst, 1_000).cookie, learned.cookie);
    assert_eq!(cached_cookie(&first, src, dst, 1_000).mss, 1460);
    assert_eq!(cached_cookie(&second, src, dst, 1_000).cookie, None);
}
