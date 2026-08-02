// What the fast-open option family CHANGES: where the queue bound and the keys
// land, what asks the namespace to draw its keys, and what a socket accepted
// from a fast-open listener comes away with.

use crate::sock::SockOpts;
use crate::sock_opts::sol_tcp::apply;
use crate::sock_opts::sol_tcp::set::Action;

#[test]
fn a_fast_open_key_is_stored_as_the_active_key_then_the_backup() {
    use crate::tcp_fastopen::{KEY_BUF_LEN, KEY_LEN};
    let opts = SockOpts::default();
    let primary = [1u8; KEY_LEN];
    let backup = [2u8; KEY_LEN];
    apply::store(&opts, &Action::FastopenKey { primary, backup: None });
    assert_eq!(opts.tcp.fastopen.keys().map(|c| c.bytes()), Some(primary.to_vec()));
    apply::store(&opts, &Action::FastopenKey { primary, backup: Some(backup) });
    let stored = opts.tcp.fastopen.keys().unwrap().bytes();
    assert_eq!(stored.len(), KEY_BUF_LEN);
    assert_eq!(&stored[..KEY_LEN], &primary[..]);
    assert_eq!(&stored[KEY_LEN..], &backup[..]);
}

#[test]
fn a_queue_bound_lands_on_the_accept_queue_and_asks_for_the_namespaces_keys() {
    let opts = SockOpts::default();
    assert_eq!(opts.tcp.fastopen.max_qlen(), 0);
    let effects = apply::store(&opts, &Action::Fastopen(16));
    assert_eq!(opts.tcp.fastopen.max_qlen(), 16);
    // Naming a bound is the moment a listener could need a cookie to mint, so
    // the namespace draws its keys then rather than at namespace creation.
    assert!(effects.fastopen_keys);
    // Nothing else asks for them.
    assert!(!apply::store(&opts, &Action::FastopenNoCookie(true)).fastopen_keys);
    assert!(!apply::store(&opts, &Action::FastopenConnect(true)).fastopen_keys);
}

#[test]
fn a_socket_accepted_from_a_listener_gets_a_fresh_fast_open_accept_queue() {
    use crate::tcp_fastopen::KEY_LEN;
    let listener = SockOpts::default();
    apply::store(&listener, &Action::Fastopen(16));
    apply::store(&listener, &Action::FastopenKey {
        primary: [7u8; KEY_LEN], backup: None });
    let child = SockOpts::default();
    child.tcp.inherit(&listener.tcp);
    // A child inheriting the bound would turn every accepted connection into
    // another fast-open listener, and inheriting the key would spread the
    // secret; its accept queue is its own.
    assert_eq!(child.tcp.fastopen.max_qlen(), 0);
    assert_eq!(child.tcp.fastopen.keys(), None);
    assert_eq!(listener.tcp.fastopen.max_qlen(), 16);
}
