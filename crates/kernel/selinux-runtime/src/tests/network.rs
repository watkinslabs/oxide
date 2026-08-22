use super::*;

use selinux::uapi::initsid::InitSid;

const STAGED: Sid = 4242;

fn staged() -> Option<Sid> { Some(STAGED) }

/// One test, not several: the staged-label reader is a process-wide slot with no
/// removal, so a second test installing it would decide the first test's answer
/// depending on which ran first. The whole ladder is walked here in order.
#[test]
fn staged_socket_label_precedes_transition_and_no_policy_keeps_the_creators_label() {
    // No reader installed: nothing is staged, so a socket takes the creating
    // thread's own label. Hosted there is no task, which is the kernel acting on
    // its own behalf and carries the kernel's label.
    assert_eq!(sockcreate_sid(), None);
    assert_eq!(create_sid("tcp_socket"), InitSid::Kernel.sid());

    set_sockcreate_sid_source(staged);
    assert_eq!(sockcreate_sid(), Some(STAGED));
    // The staged label wins over the thread's own — that is the whole point of
    // staging one.
    assert_eq!(create_sid("tcp_socket"), STAGED);
    assert_ne!(create_sid("tcp_socket"), InitSid::Kernel.sid());
}

/// The label an unconnected socket reports for its peer is a REAL label, not the
/// absence of one: it must never be the boundary's "no label" id, or an
/// unconnected socket would be indistinguishable from one on a kernel with no
/// module at all.
#[test]
fn the_unconnected_peer_label_is_unlabeled_and_never_the_absent_id() {
    assert_eq!(unlabeled(), InitSid::Unlabeled.sid());
    assert_ne!(unlabeled(), 0);
}

/// With no server installed there is no table to render from and no range to
/// move. Both answers must be defined rather than a panic: sockets are created
/// on this path during early boot, before any policy exists.
#[test]
fn with_no_server_installed_rendering_fails_and_a_range_copy_is_the_identity() {
    // `check.rs` documents that hosted tests leave the global server
    // uninstalled; this test depends on that and asserts it rather than
    // assuming it.
    assert!(!crate::installed());
    assert_eq!(context(InitSid::Kernel.sid()), Err(ContextError::InvalidLabel));
    assert_eq!(server_end_sid(InitSid::Kernel.sid(), InitSid::Init.sid()),
        InitSid::Kernel.sid());
    assert_eq!(server_end_sid(7, 9), 7);
}
