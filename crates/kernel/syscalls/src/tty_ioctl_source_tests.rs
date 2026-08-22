#[test]
fn tiocvhangup_routes_the_open_tty_through_the_canonical_hangup_owner() {
    let route = include_str!("016_ioctl/tty_ioctl.rs");
    let session = include_str!("016_ioctl/tty_ioctl/session.rs");
    assert!(route.contains("TIOCVHANGUP => session::handle"),
        "the tty ioctl dispatcher must claim TIOCVHANGUP");
    assert!(session.contains("tiocvhangup_decision(cur.has_cap(sched::cap::SYS_ADMIN))"),
        "the ioctl must use CAP_SYS_ADMIN, not vhangup(2)'s capability");
    assert!(session.contains("crate::tty_hangup::vhangup_inode(file.inode())"),
        "the fd target must reach the existing per-open revocation mechanism");
    let owner = include_str!("tty_hangup.rs");
    assert!(owner.contains("tty::hangup::hangup_session(inode.ino(), sid, fg);\n    hangup(&target, HangupKind::Vhangup);"),
        "the canonical owner must clear the session before revoking the line");
}
