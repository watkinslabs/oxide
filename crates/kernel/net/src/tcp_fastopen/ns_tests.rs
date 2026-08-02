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
