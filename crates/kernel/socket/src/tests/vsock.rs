// AF_VSOCK send division: what an out-of-band attempt imports, and which
// destination and transport errors the family reports.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::*;
use super::common::{Phased, vsock_file};
use crate::test_support::unpoliced;

#[test]
fn vsock_oob_imports_envelope_only() {
    let _policy = unpoliced();
    let task = sched::Task::new(12, "send", sched::SchedClass::Normal { weight: 1024 });
    let ctx = SendContext::new(&task);
    let target = vsock_file(Arc::new(net::vsock_socket::VsockSocket::new()));
    let mut io = Phased { target, events: Vec::new(), name: Some(alloc::vec![0; 16]) };
    assert_eq!(send_io(&ctx, net::uapi::MSG_OOB as u32, &mut io), Err(Error::Eopnotsupp));
    assert_eq!(io.events, ["file", "envelope"]);
}

struct VsockBatch { target: Arc<vfs::File>, modes: Vec<ImportMode> }
impl BatchIo for VsockBatch {
    fn file(&mut self) -> KResult<Arc<vfs::File>> { Ok(self.target.clone()) }
    fn import(&mut self, _index: u32, mode: ImportMode) -> KResult<Message> {
        self.modes.push(mode); Ok(Message::default())
    }
    fn publish(&mut self, _index: u32, _len: u32) -> KResult<()> { Ok(()) }
}

#[test]
fn vsock_batch_oob_imports_each_attempt_as_envelope_only() {
    let _policy = unpoliced();
    let task = sched::Task::new(15, "send", sched::SchedClass::Normal { weight: 1024 });
    let ctx = SendContext::new(&task);
    let target = vsock_file(Arc::new(net::vsock_socket::VsockSocket::new()));
    let mut io = VsockBatch { target, modes: Vec::new() };
    assert_eq!(send_batch(&ctx, BatchSpec { len: 1, flags: net::uapi::MSG_OOB as u32 }, &mut io),
        Err(Error::Eopnotsupp));
    assert_eq!(io.modes, [ImportMode::RawOobEnvelope]);
}

#[test]
fn vsock_destination_and_transport_errors_match_linux() {
    let _policy = unpoliced();
    let task = sched::Task::new(13, "send", sched::SchedClass::Normal { weight: 1024 });
    let ctx = SendContext::new(&task);
    let init = Arc::new(net::vsock_socket::VsockSocket::new());
    assert_eq!(send(&ctx, vsock_file(init), Message { name: Some(alloc::vec![0; 16]),
        ..Message::default() }, 0), Err(Error::Eopnotsupp));

    let owner = net::vsock::VsockOwner::from_raw(0x0c00_0042).unwrap();
    let conn = Arc::new(net::vsock::VsockConn::new(owner, 3, 62_100, 2, 1024,
        net::vsock::VsockState::Connected));
    let connected = Arc::new(net::vsock_socket::VsockSocket::new());
    *connected.kind.lock() = net::vsock_socket::VsockKind::Conn(conn);
    let file = vsock_file(connected);
    assert_eq!(send(&ctx, file.clone(), Message { name: Some(alloc::vec![0; 16]),
        ..Message::default() }, 0), Err(Error::Eisconn));
    assert_eq!(send(&ctx, file.clone(), Message { name: Some(Vec::new()),
        ..Message::default() }, 0), Err(Error::Eisconn));
    // The connection above carries no transport (nothing published an endpoint
    // for this owner), so a payload send reports ENOTCONN — the same answer a
    // connection-oriented socket gives when it has no transport or has not
    // reached the established state. EPIPE belongs to a shut direction and
    // EINTR to an interrupted wait; neither applies before a transport exists,
    // and an untimed interrupted wait would report ERESTARTSYS rather than
    // EINTR anyway (`net::sock_intr`).
    assert_eq!(send(&ctx, file, Message { payload: alloc::vec![1], requested_len: 1,
        name: None, ..Message::default() }, 0), Err(Error::Enotconn));
}
