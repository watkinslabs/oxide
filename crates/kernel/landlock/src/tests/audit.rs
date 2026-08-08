use alloc::vec::Vec;

use super::*;

fn text(v: &[u8]) -> &str { core::str::from_utf8(v).expect("record text is ASCII") }

#[test]
fn every_filesystem_right_this_kernel_enforces_has_a_name() {
    let mut i = 0;
    let mut bit: AccessMask = 1;
    while bit <= LAST_ACCESS_FS {
        assert_ne!(blocker_name(RequestType::FsAccess, i), b"unknown", "fs bit {i}");
        bit <<= 1;
        i += 1;
    }
    assert_eq!(i, 17, "the named list covers exactly the enforced rights");
}

#[test]
fn every_network_right_has_a_name() {
    let mut i = 0;
    let mut bit: AccessMask = 1;
    while bit <= LAST_ACCESS_NET {
        assert_ne!(blocker_name(RequestType::NetAccess, i), b"unknown", "net bit {i}");
        bit <<= 1;
        i += 1;
    }
    assert_eq!(i, 4);
}

/// A record must never omit a blocker it cannot name: a denial with no cause
/// would let an auditor conclude the wrong thing.
#[test]
fn an_unnamed_bit_still_produces_a_blocker() {
    assert_eq!(blocker_name(RequestType::FsAccess, 63), b"unknown");
    let mut b = Vec::new();
    blockers(&mut b, RequestType::FsAccess, 1 << 40);
    assert_eq!(text(&b), "unknown");
}

#[test]
fn several_missing_rights_are_listed_comma_separated_low_bit_first() {
    let mut b = Vec::new();
    blockers(&mut b, RequestType::FsAccess,
        ACCESS_FS_READ_FILE | ACCESS_FS_EXECUTE | ACCESS_FS_TRUNCATE);
    assert_eq!(text(&b), "fs.execute,fs.read_file,fs.truncate");
}

/// A scope denial names no rights bit at all, so the request's own name is the
/// blocker.
#[test]
fn a_scope_denial_names_the_scope() {
    let mut b = Vec::new();
    blockers(&mut b, RequestType::ScopeSignal, 0);
    assert_eq!(text(&b), "scope.signal");
    let mut b = Vec::new();
    blockers(&mut b, RequestType::ScopeAbstractUnixSocket, 0);
    assert_eq!(text(&b), "scope.abstract_unix_socket");
}

#[test]
fn a_denial_record_names_the_domain_in_hex_and_its_blockers() {
    let b = access_body(0x2a, RequestType::NetAccess, ACCESS_NET_BIND_TCP);
    assert_eq!(text(&b), "domain=2a blockers=net.bind_tcp");
}

#[test]
fn a_domain_record_describes_who_built_it() {
    let d = DomainDetails { pid: 91, uid: 1000, exe: Vec::from(*b"/usr/bin/sandbox"),
                            comm: Vec::from(*b"sandbox") };
    assert_eq!(text(&domain_body(7, &d)),
        "domain=7 status=allocated mode=enforcing pid=91 uid=1000 \
         exe=\"/usr/bin/sandbox\" comm=\"sandbox\"");
}

/// The path and the command name came from userspace, so a value that could
/// split a field is hex-encoded rather than quoted.
#[test]
fn a_domain_record_encodes_a_hostile_path_as_hex() {
    let d = DomainDetails { pid: 1, uid: 0, exe: Vec::from(*b"/a b"), comm: Vec::new() };
    let body = domain_body(1, &d);
    let t = text(&body);
    assert!(t.contains("exe=2F612062 "), "{t}");
    assert!(t.ends_with("comm=(null)"), "{t}");
}

#[test]
fn a_teardown_record_carries_the_total_denial_count() {
    assert_eq!(text(&drop_body(0xff, 12)), "domain=ff status=deallocated denials=12");
}

/// Silencing a denial that includes a right the policy never asked to silence
/// would hide the part its author wanted to see.
#[test]
fn a_filesystem_denial_is_quiet_only_when_the_mask_covers_every_missing_right() {
    let missing = ACCESS_FS_READ_FILE | ACCESS_FS_WRITE_FILE;
    assert!(quieted(RequestType::FsAccess, true, missing, missing, 0, 0));
    assert!(!quieted(RequestType::FsAccess, true, missing, ACCESS_FS_READ_FILE, 0, 0));
    assert!(quieted(RequestType::FsAccess, true, ACCESS_FS_READ_FILE, missing, 0, 0));
}

/// The mask alone is not enough: the OBJECT has to have been marked quiet by a
/// rule of the layer that denied, or every denial of that right anywhere would
/// go silent.
#[test]
fn a_filesystem_denial_needs_the_object_marked_quiet_too() {
    let missing = ACCESS_FS_READ_FILE;
    assert!(!quieted(RequestType::FsAccess, false, missing, missing, 0, 0));
    assert!(!quieted(RequestType::NetAccess, false, ACCESS_NET_BIND_TCP, 0,
        ACCESS_NET_BIND_TCP, 0));
}

#[test]
fn a_network_denial_reads_the_network_mask_not_the_filesystem_one() {
    let m = ACCESS_NET_CONNECT_TCP;
    assert!(quieted(RequestType::NetAccess, true, m, 0, m, 0));
    assert!(!quieted(RequestType::NetAccess, true, m, m, 0, 0));
}

/// A scope names no object to mark, so the layer's scope mask alone decides.
#[test]
fn a_scope_denial_is_quiet_from_the_mask_alone() {
    assert!(quieted(RequestType::ScopeSignal, false, 0, 0, 0, SCOPE_SIGNAL));
    assert!(!quieted(RequestType::ScopeSignal, false, 0, 0, 0,
        SCOPE_ABSTRACT_UNIX_SOCKET));
    assert!(quieted(RequestType::ScopeAbstractUnixSocket, false, 0, 0, 0,
        SCOPE_ABSTRACT_UNIX_SOCKET | SCOPE_SIGNAL));
    assert!(!quieted(RequestType::ScopeAbstractUnixSocket, false, 0, 0, 0, 0));
}

/// With no per-thread reader installed, every layer reads as "not this
/// execution" — the same answer a thread that has just been replaced gives.
#[test]
fn an_uninstalled_execution_reader_reports_no_layer() {
    assert!(!same_execution(0));
    assert!(!same_execution(MAX_NUM_LAYERS));
    assert!(!same_execution(usize::MAX));
}
