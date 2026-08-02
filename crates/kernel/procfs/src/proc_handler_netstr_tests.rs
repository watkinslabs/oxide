use alloc::sync::Arc;
use network_namespace::NetworkNamespaceRef;

use super::PerNetStrHook;
use crate::proc_handler::ProcHandler;

// The bound leaf resolves its namespace by CALLING `current()`, so a sibling
// storing its own namespace here between this test's `bind()` and its `store()`
// would redirect the write. One claim per test body; poison recovered so one
// failure stays one failure.
static CURRENT: std::sync::Mutex<Option<NetworkNamespaceRef>> = std::sync::Mutex::new(None);
static CURRENT_CLAIM: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn claim_current() -> std::sync::MutexGuard<'static, ()> {
    CURRENT_CLAIM.lock().unwrap_or_else(|e| e.into_inner())
}

fn current() -> NetworkNamespaceRef {
    Arc::clone(CURRENT.lock().unwrap().as_ref().unwrap())
}

fn get(namespace: &NetworkNamespaceRef) -> alloc::vec::Vec<u8> {
    net::tcp_fastopen::format_hex(net::tcp_fastopen::ns_keys(namespace).as_ref())
}

fn set(namespace: &NetworkNamespaceRef, src: &[u8]) -> Result<(), ()> {
    let ctx = net::tcp_fastopen::parse_hex(src).ok_or(())?;
    net::tcp_fastopen::set_ns_keys(namespace, ctx);
    Ok(())
}

fn namespace() -> NetworkNamespaceRef {
    let initial_user = namespace_identity::initial(namespace_identity::NamespaceKind::User);
    let ns = network_namespace::allocate(initial_user).unwrap();
    net::net_ns::materialize_state(&ns);
    ns
}

fn leaf(owner_only: bool) -> PerNetStrHook {
    PerNetStrHook { current_ns: current, get, set, owner_only }
}

#[test]
fn a_secret_leaf_is_owner_only_and_an_ordinary_one_is_not() {
    assert!(leaf(true).owner_only());
    assert!(!leaf(false).owner_only());
    // Owner-only does not mean read-only: the value is still writable.
    assert!(leaf(true).writable());
}

#[test]
fn the_read_reports_the_namespaces_own_value_with_a_trailing_newline() {
    let _claim = claim_current();
    let ns = namespace();
    *CURRENT.lock().unwrap() = Some(Arc::clone(&ns));
    let text = leaf(true).format();
    assert_eq!(text.last(), Some(&b'\n'));
    assert_eq!(&text[..text.len() - 1],
        &net::tcp_fastopen::format_hex(None)[..]);
}

#[test]
fn a_write_is_parsed_and_lands_in_the_namespace_the_leaf_was_opened_in() {
    let _claim = claim_current();
    let opened_in = namespace();
    let switched_to = namespace();
    *CURRENT.lock().unwrap() = Some(Arc::clone(&opened_in));
    let bound = leaf(true).bind().unwrap();
    // The task moves namespaces after the open; the write must still land in
    // the namespace the file names.
    *CURRENT.lock().unwrap() = Some(Arc::clone(&switched_to));
    bound.store(b"01020304-05060708-090a0b0c-0d0e0f10\n").unwrap();
    let keys = net::tcp_fastopen::ns_keys(&opened_in).expect("the written keys");
    assert_eq!(keys.primary.as_bytes(),
        &[0x04, 0x03, 0x02, 0x01, 0x08, 0x07, 0x06, 0x05,
          0x0c, 0x0b, 0x0a, 0x09, 0x10, 0x0f, 0x0e, 0x0d]);
    assert_eq!(net::tcp_fastopen::ns_keys(&switched_to), None);
    // And it reads back as it was written.
    assert_eq!(bound.format(), b"01020304-05060708-090a0b0c-0d0e0f10\n".to_vec());
}

#[test]
fn a_malformed_write_is_refused_and_leaves_the_live_value_alone() {
    let _claim = claim_current();
    let ns = namespace();
    *CURRENT.lock().unwrap() = Some(Arc::clone(&ns));
    let bound = leaf(true).bind().unwrap();
    bound.store(b"1-2-3-4\n").unwrap();
    let before = net::tcp_fastopen::ns_keys(&ns);
    assert!(before.is_some());
    for bad in [&b"not-a-key"[..], b"1-2-3", b"", b"1-2-3-4,zz"] {
        assert!(bound.store(bad).is_err());
    }
    assert_eq!(net::tcp_fastopen::ns_keys(&ns), before);
}
