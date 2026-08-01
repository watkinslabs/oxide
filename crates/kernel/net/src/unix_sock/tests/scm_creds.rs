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
        vfs::File::new_at(ino, d, vfs::OpenFlags::O_RDWR, 0, vfs::FileCred::root())
    };
    pair.write_with_rights_and_creds(UnixEnd::A, b"rights", classify_files(alloc::vec![file]), cred).unwrap();
    let (_, first_control, _) = pair.read_stream(UnixEnd::B, 64);
    assert!(!first_control.stops_waitall(true), "equal credentials permit the next receive step");
    let (_, rights, _) = pair.read_stream(UnixEnd::B, 64);
    assert_eq!(rights.len(), 1);
    assert!(rights.stops_waitall(true), "SCM_RIGHTS remains a waitall stop");
}

#[test]
fn read_without_a_control_buffer_stops_after_a_rights_bearing_segment() {
    let _serial = test_guard();
    let pair = UnixPair::new();
    let file = super::anon_file();
    pair.write_with_fds(UnixEnd::A, b"aaa", alloc::vec![file.clone()]).unwrap();
    pair.write(UnixEnd::A, b"bbb").unwrap();
    // A read(2) has no cmsg to take the descriptor, yet the boundary the
    // descriptor creates still ends the receive: "bbb" is a separate read.
    assert_eq!(pair.read(UnixEnd::B, 64), b"aaa");
    assert_eq!(pair.read(UnixEnd::B, 64), b"bbb");
    // The discarded descriptor is released, not requeued and not leaked.
    assert_eq!(alloc::sync::Arc::strong_count(&file), 1);
}

#[test]
fn read_without_a_control_buffer_glues_segments_from_one_sender() {
    let _serial = test_guard();
    let pair = UnixPair::new();
    pair.write(UnixEnd::A, b"aaa").unwrap();
    pair.write(UnixEnd::A, b"bbb").unwrap();
    assert_eq!(pair.read(UnixEnd::B, 64), b"aaabbb");
}

#[test]
fn read_stops_at_a_sender_change_only_when_the_socket_passes_credentials() {
    let _serial = test_guard();
    let pair = UnixPair::new();
    pair.write_with_rights_and_creds(UnixEnd::A, b"first", classify_files(alloc::vec![]), (11, 12, 13)).unwrap();
    pair.write_with_rights_and_creds(UnixEnd::A, b"second", classify_files(alloc::vec![]), (21, 22, 23)).unwrap();
    assert_eq!(pair.read_passcred(UnixEnd::B, 64, true), b"first",
        "credential passing on: different writers are never glued");
    assert_eq!(pair.read_passcred(UnixEnd::B, 64, true), b"second");

    let plain = UnixPair::new();
    plain.write_with_rights_and_creds(UnixEnd::A, b"first", classify_files(alloc::vec![]), (11, 12, 13)).unwrap();
    plain.write_with_rights_and_creds(UnixEnd::A, b"second", classify_files(alloc::vec![]), (21, 22, 23)).unwrap();
    assert_eq!(plain.read_passcred(UnixEnd::B, 64, false), b"firstsecond",
        "credential passing off: the sender's identity is not a boundary");
}

#[test]
fn a_partly_drained_segment_still_names_its_sender() {
    let _serial = test_guard();
    let pair = UnixPair::new();
    pair.write_with_rights_and_creds(UnixEnd::A, b"abcdef", classify_files(alloc::vec![]), (71, 72, 73)).unwrap();
    assert_eq!(pair.read(UnixEnd::B, 2), b"ab");
    // The remaining bytes belong to the same message, so a following recvmsg
    // reports the credential that message was stamped with.
    let (rest, _, cred) = pair.read_stream(UnixEnd::B, 64);
    assert_eq!(rest, b"cdef");
    assert_eq!(cred, Some((71, 72, 73)));
}

#[test]
fn a_partly_drained_segment_gives_up_its_descriptors_immediately() {
    let _serial = test_guard();
    let pair = UnixPair::new();
    let file = super::anon_file();
    pair.write_with_fds(UnixEnd::A, b"abcdef", alloc::vec![file.clone()]).unwrap();
    assert_eq!(pair.read(UnixEnd::B, 2), b"ab");
    assert_eq!(alloc::sync::Arc::strong_count(&file), 1,
        "descriptors go with the first byte handed over without a cmsg");
    let (rest, files, _) = pair.read_stream(UnixEnd::B, 64);
    assert_eq!(rest, b"cdef");
    assert_eq!(files.len(), 0, "a descriptor is delivered once, never twice");
}
