use crate::{classify_files, UnixEnd, UnixMsgPair, UnixPair};
use super::test_guard;

#[test]
fn supplied_stream_credentials_reach_receiver() {
    let _serial = test_guard();
    let pair = UnixPair::new();
    pair.write_with_rights_and_creds(UnixEnd::A, b"x", classify_files(alloc::vec![]), (41, 42, 43)).unwrap();
    assert_eq!(pair.read_stream(UnixEnd::B, 1).2, Some((41, 42, 43)));
}

#[test]
fn supplied_record_credentials_reach_receiver() {
    let _serial = test_guard();
    let pair = UnixMsgPair::new();
    pair.send_with_rights_and_creds(UnixEnd::A, b"x", classify_files(alloc::vec![]), (51, 52, 53)).unwrap();
    assert_eq!(pair.recv_msg(UnixEnd::B, 1).unwrap().creds, (51, 52, 53));
}

#[test]
fn stream_different_credentials_stop_waitall_merge() {
    let _serial = test_guard();
    let pair = UnixPair::new();
    pair.write_with_rights_and_creds(UnixEnd::A, b"first", classify_files(alloc::vec![]), (11, 12, 13)).unwrap();
    pair.write_with_rights_and_creds(UnixEnd::A, b"second", classify_files(alloc::vec![]), (21, 22, 23)).unwrap();
    let (first, boundary, cred) = pair.read_stream(UnixEnd::B, 64);
    assert_eq!(first, b"first");
    assert_eq!(boundary.len(), 0, "credential stop carries no descriptors");
    assert!(boundary.stops_waitall(true), "MSG_WAITALL observes the credential boundary");
    assert!(!boundary.stops_waitall(false), "disabled SO_PASSCRED does not expose credential boundaries");
    assert_eq!(cred, Some((11, 12, 13)));
    assert_eq!(pair.read_stream(UnixEnd::B, 64).0, b"second");
}

#[test]
fn stream_equal_credentials_allow_waitall_merge() {
    let _serial = test_guard();
    let pair = UnixPair::new();
    let cred = (31, 32, 33);
    pair.write_with_rights_and_creds(UnixEnd::A, b"first", classify_files(alloc::vec![]), cred).unwrap();
    pair.write_with_rights_and_creds(UnixEnd::A, b"second", classify_files(alloc::vec![]), cred).unwrap();
    let (first, boundary, _) = pair.read_stream(UnixEnd::B, 64);
    assert_eq!(first, b"first");
    assert!(!boundary.stops_waitall(true), "equal sender credentials do not stop MSG_WAITALL");
    assert_eq!(pair.read_stream(UnixEnd::B, 64).0, b"second");
}

#[test]
fn stream_peek_reports_different_credential_boundary() {
    let _serial = test_guard();
    let pair = UnixPair::new();
    pair.write_with_rights_and_creds(UnixEnd::A, b"one", classify_files(alloc::vec![]), (41, 42, 43)).unwrap();
    pair.write_with_rights_and_creds(UnixEnd::A, b"two", classify_files(alloc::vec![]), (51, 52, 53)).unwrap();
    let (data, boundary, cred) = pair.read_stream_with_opts(UnixEnd::B, 64, true,
        |data, _, _| Ok::<_, ()>((data.to_vec(), data.len()))).unwrap().unwrap();
    assert_eq!(data, b"one");
    assert!(boundary.stops_waitall(true));
    assert_eq!(cred, Some((41, 42, 43)));
    assert_eq!(pair.read_stream(UnixEnd::B, 64).0, b"one");
}

#[test]
fn stream_rights_still_stop_waitall_with_equal_credentials() {
    let _serial = test_guard();
    let pair = UnixPair::new();
    let cred = (61, 62, 63);
    pair.write_with_rights_and_creds(UnixEnd::A, b"plain", classify_files(alloc::vec![]), cred).unwrap();
    let file = {
        struct Ops;
        impl vfs::FileOps for Ops {}
        let ino = vfs::InodeBuilder::new(0xB820, vfs::mk_mode(vfs::FileType::Socket, 0o600),
            vfs::default_inode_ops(), alloc::sync::Arc::new(Ops)).build();
        let d = vfs::Dentry::new(None, "rights".into(), alloc::sync::Arc::clone(&ino));
        vfs::File::new_at(ino, d, vfs::OpenFlags::O_RDWR, 0, vfs::Cred::root())
    };
    pair.write_with_rights_and_creds(UnixEnd::A, b"rights", classify_files(alloc::vec![file]), cred).unwrap();
    let (_, first_control, _) = pair.read_stream(UnixEnd::B, 64);
    assert!(!first_control.stops_waitall(true), "equal credentials permit the next receive step");
    let (_, rights, _) = pair.read_stream(UnixEnd::B, 64);
    assert_eq!(rights.len(), 1);
    assert!(rights.stops_waitall(true), "SCM_RIGHTS remains a waitall stop");
}
