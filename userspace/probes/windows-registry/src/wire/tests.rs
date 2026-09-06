use super::*;
use std::io::Cursor;

struct Peer { input: Cursor<Vec<u8>>, output: Vec<u8> }
impl Read for Peer {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> { self.input.read(bytes) }
}
impl Write for Peer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> { self.output.extend_from_slice(bytes); Ok(bytes.len()) }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}
fn peer(bytes: Vec<u8>) -> Peer { Peer { input: Cursor::new(bytes), output: Vec::new() } }

#[test]
fn only_empty_header_is_clean_disconnect() {
    let mut empty = peer(Vec::new());
    assert!(serve_requests(&mut empty, |_| panic!("EOF cannot execute")).is_ok());
    for count in 1..4 {
        let mut truncated = peer(vec![1; count]);
        let error = serve_requests(&mut truncated, |_| panic!("partial header cannot execute")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        assert!(truncated.output.is_empty());
    }
}

#[test]
fn failed_transaction_has_no_success_response() {
    let request = vec![registry_wire::OPEN, 1, 0, 0, 0, 0];
    let mut bytes = (request.len() as u32).to_le_bytes().to_vec(); bytes.extend(request);
    let mut stream = peer(bytes);
    let mut calls = 0;
    let error = serve_requests(&mut stream, |request| {
        assert!(matches!(request, Ok(Request::Open { root: Root::CurrentUser, .. })));
        calls += 1; Err(io::Error::other("fixture persistence failure"))
    }).unwrap_err();
    assert_eq!(calls, 1); assert_eq!(error.kind(), io::ErrorKind::Other);
    assert!(stream.output.is_empty());
}
