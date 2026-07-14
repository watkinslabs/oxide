use crate::{classify_files, UnixEnd, UnixMsgPair, UnixPair};

#[test]
fn supplied_stream_credentials_reach_receiver() {
    let pair = UnixPair::new();
    pair.write_with_rights_and_creds(UnixEnd::A, b"x", classify_files(alloc::vec![]), (41, 42, 43)).unwrap();
    assert_eq!(pair.read_stream(UnixEnd::B, 1).2, Some((41, 42, 43)));
}

#[test]
fn supplied_record_credentials_reach_receiver() {
    let pair = UnixMsgPair::new();
    pair.send_with_rights_and_creds(UnixEnd::A, b"x", classify_files(alloc::vec![]), (51, 52, 53)).unwrap();
    assert_eq!(pair.recv_msg(UnixEnd::B, 1).unwrap().creds, (51, 52, 53));
}
