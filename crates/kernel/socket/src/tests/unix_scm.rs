// AF_UNIX SCM_RIGHTS send accounting: the passed files are pinned before the
// payload can fault, and the pin survives the exact fd being reused underneath
// it, so a failed send leaves the sender's reference counts where it found them.

use alloc::sync::Arc;

use crate::*;
use super::common::{file, inet_file, rights_control};
use crate::test_support::unpoliced;

struct UnixMalformedPayload { target: Arc<vfs::File>, fd: i32, payload_called: bool }

impl MessageIo for UnixMalformedPayload {
    fn file(&mut self) -> KResult<Arc<vfs::File>> { Ok(self.target.clone()) }
    fn import(&mut self, _mode: ImportMode) -> KResult<Message> { Err(Error::Eio) }
    fn import_envelope(&mut self) -> KResult<Option<Message>> {
        Ok(Some(Message { requested_len: 1, control: rights_control(&[self.fd]),
            name: Some(alloc::vec::Vec::new()), ..Message::default() }))
    }
    fn import_payload(&mut self, _message: &mut Message) -> KResult<()> {
        self.payload_called = true;
        Err(Error::Efault)
    }
}

#[test]
fn unix_scm_is_pinned_before_atomic_payload_fault_and_cleaned_on_failure() {
    let _policy = unpoliced();
    let task = sched::Task::new(14, "send", sched::SchedClass::Normal { weight: 1024 });
    let table = Arc::new(vfs::FdTable::new());
    // SAFETY: hosted test has exclusive ownership of this unscheduled task.
    unsafe { task.replace_fd_table(Some(table.clone())); }
    let held = file(vfs::OpenFlags::O_RDWR);
    let fd = table.alloc(held.clone()).unwrap();
    let baseline = Arc::strong_count(&held);
    let target = inet_file(Arc::new(net::sock::InetSocket::new_unix_dgram()));
    let ctx = SendContext::new(&task);
    let message = Message { payload_faulted: true, requested_len: 1,
        control: rights_control(&[fd, i32::MAX]), ..Message::default() };

    assert_eq!(send(&ctx, target, message, 0), Err(Error::Ebadf));
    assert_eq!(Arc::strong_count(&held), baseline);

    let target = inet_file(Arc::new(net::sock::InetSocket::new_unix_dgram()));
    let mut io = UnixMalformedPayload { target, fd, payload_called: false };
    assert_eq!(send_io(&ctx, 0, &mut io), Err(Error::Einval));
    assert!(!io.payload_called);
    assert_eq!(Arc::strong_count(&held), baseline);
}

struct ReuseDuringPayload {
    target: Arc<vfs::File>, table: Arc<vfs::FdTable>, fd: i32, held: Arc<vfs::File>,
}

impl MessageIo for ReuseDuringPayload {
    fn file(&mut self) -> KResult<Arc<vfs::File>> { Ok(self.target.clone()) }
    fn import(&mut self, _mode: ImportMode) -> KResult<Message> { Err(Error::Eio) }
    fn import_envelope(&mut self) -> KResult<Option<Message>> {
        Ok(Some(Message { requested_len: 1, control: rights_control(&[self.fd]),
            ..Message::default() }))
    }
    fn import_payload(&mut self, message: &mut Message) -> KResult<()> {
        assert_eq!(Arc::strong_count(&self.held), 4);
        self.table.close(self.fd).unwrap();
        assert_eq!(self.table.alloc(file(vfs::OpenFlags::O_RDWR)).unwrap(), self.fd);
        assert_eq!(Arc::strong_count(&self.held), 3);
        message.payload_faulted = true;
        Ok(())
    }
}

#[test]
fn unix_scm_pin_survives_exact_fd_reuse_during_payload_import() {
    let _policy = unpoliced();
    let task = sched::Task::new(17, "send", sched::SchedClass::Normal { weight: 1024 });
    let table = Arc::new(vfs::FdTable::new());
    // SAFETY: hosted test has exclusive ownership of this unscheduled task.
    unsafe { task.replace_fd_table(Some(table.clone())); }
    let held = file(vfs::OpenFlags::O_RDWR);
    let fd = table.alloc(held.clone()).unwrap();
    let socket = Arc::new(net::sock::InetSocket::new_unix());
    *socket.kind.lock() = net::sock::SockKind::UnixMsgPair(net::UnixMsgPair::new(), net::UnixEnd::A);
    let mut io = ReuseDuringPayload { target: inet_file(socket), table, fd, held: held.clone() };
    assert_eq!(send_io(&SendContext::new(&task), 0, &mut io), Err(Error::Efault));
    assert_eq!(Arc::strong_count(&held), 2);
}

struct BatchReuseDuringPayload {
    target: Arc<vfs::File>, table: Arc<vfs::FdTable>, fd: i32, held: Arc<vfs::File>,
    published: bool,
}

impl BatchIo for BatchReuseDuringPayload {
    fn file(&mut self) -> KResult<Arc<vfs::File>> { Ok(self.target.clone()) }
    fn import(&mut self, _index: u32, _mode: ImportMode) -> KResult<Message> { Err(Error::Eio) }
    fn import_envelope(&mut self, index: u32) -> KResult<Option<Message>> {
        assert_eq!(index, 0);
        Ok(Some(Message { requested_len: 1, control: rights_control(&[self.fd]),
            ..Message::default() }))
    }
    fn import_payload(&mut self, index: u32, message: &mut Message) -> KResult<()> {
        assert_eq!(index, 0);
        assert_eq!(Arc::strong_count(&self.held), 4);
        self.table.close(self.fd).unwrap();
        assert_eq!(self.table.alloc(file(vfs::OpenFlags::O_RDWR)).unwrap(), self.fd);
        assert_eq!(Arc::strong_count(&self.held), 3);
        message.payload_faulted = true;
        Ok(())
    }
    fn publish(&mut self, _index: u32, _len: u32) -> KResult<()> {
        self.published = true;
        Ok(())
    }
}

#[test]
fn sendmmsg_scm_pin_survives_exact_fd_reuse_during_payload_import() {
    let _policy = unpoliced();
    let task = sched::Task::new(19, "send", sched::SchedClass::Normal { weight: 1024 });
    let table = Arc::new(vfs::FdTable::new());
    // SAFETY: hosted test has exclusive ownership of this unscheduled task.
    unsafe { task.replace_fd_table(Some(table.clone())); }
    let held = file(vfs::OpenFlags::O_RDWR);
    let fd = table.alloc(held.clone()).unwrap();
    let socket = Arc::new(net::sock::InetSocket::new_unix());
    *socket.kind.lock() = net::sock::SockKind::UnixMsgPair(net::UnixMsgPair::new(), net::UnixEnd::A);
    let mut io = BatchReuseDuringPayload { target: inet_file(socket), table, fd,
        held: held.clone(), published: false };
    assert_eq!(send_batch(&SendContext::new(&task), BatchSpec { len: 1, flags: 0 }, &mut io),
        Err(Error::Efault));
    assert!(!io.published);
    assert_eq!(Arc::strong_count(&held), 2);
}
