// Single-message send ordering: what the target classification retains, and
// which envelope answers precede payload materialization.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::*;
use super::common::{Phased, file, inet_file, invalid_credentials_control, netlink_file};
use crate::test_support::unpoliced;

#[test]
fn classification_retains_original_file_across_fd_reuse() {
    let table = vfs::FdTable::new();
    let original = file(vfs::OpenFlags::O_RDWR);
    let fd = table.alloc(original).unwrap();
    let target = SendFile::new(table.get(fd).unwrap());
    table.close(fd).unwrap();
    let replacement = file(vfs::OpenFlags::O_RDWR | vfs::OpenFlags::O_NONBLOCK);
    assert_eq!(table.alloc(replacement.clone()).unwrap(), fd);
    assert!(!target.nonblock());
    assert!(!Arc::ptr_eq(target.file(), &replacement));
}

struct Single { target: Arc<vfs::File>, imported: bool }

impl MessageIo for Single {
    fn file(&mut self) -> KResult<Arc<vfs::File>> { Ok(self.target.clone()) }
    fn import(&mut self, _mode: ImportMode) -> KResult<Message> {
        self.imported = true;
        Ok(Message::default())
    }
}

#[test]
fn single_send_rejects_regular_file_before_message_import() {
    let task = sched::Task::new(9, "send", sched::SchedClass::Normal { weight: 1024 });
    let ctx = SendContext::new(&task);
    let mut io = Single { target: file(vfs::OpenFlags::O_RDWR), imported: false };
    assert_eq!(send_io(&ctx, 0, &mut io), Err(Error::Enotsock));
    assert!(!io.imported);
}

struct EnvelopeProbe { target: Arc<vfs::File>, message: Message, payload_called: bool }

impl MessageIo for EnvelopeProbe {
    fn file(&mut self) -> KResult<Arc<vfs::File>> { Ok(self.target.clone()) }
    fn import(&mut self, _mode: ImportMode) -> KResult<Message> { Err(Error::Eio) }
    fn import_envelope(&mut self) -> KResult<Option<Message>> { Ok(Some(self.message.clone())) }
    fn import_payload(&mut self, _message: &mut Message) -> KResult<()> {
        self.payload_called = true;
        Err(Error::Efault)
    }
}

#[test]
fn netlink_prepares_oob_length_control_and_address_in_linux_order() {
    let _policy = unpoliced();
    let task = sched::Task::new(18, "send", sched::SchedClass::Normal { weight: 1024 });
    let ctx = SendContext::new(&task);
    let malformed = Message { requested_len: 1, control: invalid_credentials_control(),
        name: Some(Vec::new()), ..Message::default() };
    let mut io = EnvelopeProbe { target: netlink_file(), message: malformed.clone(),
        payload_called: false };
    assert_eq!(send_io(&ctx, 0, &mut io), Err(Error::Esrch));
    assert!(!io.payload_called);

    let mut zero = malformed.clone(); zero.requested_len = 0;
    let mut io = EnvelopeProbe { target: netlink_file(), message: zero, payload_called: false };
    assert_eq!(send_io(&ctx, 0, &mut io), Err(Error::Enodata));
    assert!(!io.payload_called);

    let mut io = EnvelopeProbe { target: netlink_file(), message: malformed, payload_called: false };
    assert_eq!(send_io(&ctx, net::uapi::MSG_OOB as u32, &mut io), Err(Error::Eopnotsupp));
    assert!(!io.payload_called);
    assert_eq!(Error::Enodata.errno(), 61);
}

#[test]
fn sendto_rejects_address_before_payload_materialization() {
    let _policy = unpoliced();
    let task = sched::Task::new(11, "send", sched::SchedClass::Normal { weight: 1024 });
    let ctx = SendContext::new(&task);
    let mut io = Phased { target: netlink_file(), events: Vec::new(), name: Some(Vec::new()) };
    assert_eq!(send_io(&ctx, 0, &mut io), Err(Error::Einval));
    assert_eq!(io.events, ["file", "envelope"]);
}

#[test]
fn udp_sendmsg_rejects_destination_before_payload_materialization() {
    let _policy = unpoliced();
    let task = sched::Task::new(16, "send", sched::SchedClass::Normal { weight: 1024 });
    let ctx = SendContext::new(&task);
    let target = inet_file(Arc::new(net::sock::InetSocket::new_udp()));
    let mut io = Phased { target, events: Vec::new(), name: Some(Vec::new()) };
    assert_eq!(send_io(&ctx, 0, &mut io), Err(Error::Einval));
    assert_eq!(io.events, ["file", "envelope"]);
}

#[test]
fn vfs_errors_keep_their_exact_errno() {
    for error in [vfs::VfsError::Eintr, vfs::VfsError::Enodev, vfs::VfsError::Eisdir,
        vfs::VfsError::Enospc, vfs::VfsError::Enotempty, vfs::VfsError::Euclean,
        vfs::VfsError::Edquot, vfs::VfsError::Ecanceled]
    {
        assert_eq!(Error::from(error).errno(), error as i32);
    }
}
