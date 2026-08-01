// The send path's two Landlock hooks, checked where they must sit.
//
// Neither hook can be driven behaviourally from a hosted build — the domain is
// read off the running task and there is none — so what these guard is the
// thing that actually goes wrong: the call disappearing, drifting ahead of the
// validation whose error it would mask, or asking for the wrong operation.
// `net::landlock_addr` carries the behavioural coverage of the decision itself.

/// Byte offset of `needle` in `body`, or a failure naming what is missing.
/// # C: O(len)
fn at(body: &str, needle: &str) -> usize {
    body.find(needle).unwrap_or_else(|| panic!("missing call site: {needle}"))
}

#[test]
fn a_send_that_names_a_recipient_asks_for_its_port_rights() {
    let source = include_str!("../send.rs");
    let body = &source[at(source, "pub(crate) fn prepare(")..];
    // The right is asked for as a send, not as a connect: the two differ on an
    // unspecified family from an IPv6 socket.
    let hook = at(body, "net::landlock_addr::check_send_addr(socket, name)");
    // Only a send that carries an address is checked; an already-connected
    // socket names no new port.
    let guard = at(body, "if let Some(name) = message.name.as_deref() {");
    assert!(guard < hook);
    // After the family and length parse, so a malformed address keeps its own
    // error instead of reporting a permission one.
    assert!(at(body, "crate::address::inet(message.name.as_deref())?") < guard);
    assert_eq!(body.matches("check_send_addr").count(), 1);
}

#[test]
fn resolving_a_pathname_unix_recipient_is_gated_after_the_socket_type_check() {
    let source = include_str!("../address.rs");
    let body = &source[at(source, "fn resolve_unix(")..];
    let hook = at(body, "net::landlock_addr::check_unix_resolve(&found, &addr)");
    // A name that is not a socket keeps ECONNREFUSED; only a real socket is
    // subject to the resolve right.
    assert!(at(body, "found.inode.file_type() != vfs::FileType::Socket") < hook);
    // Abstract names return before the lookup and never reach the hook.
    assert!(at(body, "net::unix_path_is_abstract(&path)") < hook);
    assert_eq!(body.matches("check_unix_resolve").count(), 1);
}
