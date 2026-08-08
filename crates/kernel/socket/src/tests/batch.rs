// `sendmmsg` division of labour: one message imported and published at a time,
// the completed prefix an interrupted or faulting entry leaves behind, and the
// order fd validation and the Linux entry cap are applied in.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use crate::*;
use super::common::{file, netlink_file, valid_netlink_payload};
use crate::test_support::unpoliced;

struct Batch { imported: Vec<u32>, published: Vec<(u32, u32)> }

impl BatchIo for Batch {
    fn file(&mut self) -> KResult<Arc<vfs::File>> { Ok(netlink_file()) }

    fn import(&mut self, index: u32, mode: ImportMode) -> KResult<Message> {
        let _ = (index, mode);
        Err(Error::Eio)
    }

    fn import_envelope(&mut self, index: u32) -> KResult<Option<Message>> {
        self.imported.push(index);
        Ok(Some(Message { requested_len: 16, ..Message::default() }))
    }

    fn import_payload(&mut self, index: u32, message: &mut Message) -> KResult<()> {
        message.payload = valid_netlink_payload(index);
        Ok(())
    }

    fn publish(&mut self, index: u32, len: u32) -> KResult<()> {
        self.published.push((index, len)); Ok(())
    }
}

#[test]
fn batch_imports_and_publishes_one_message_at_a_time() {
    let _policy = unpoliced();
    let task = sched::Task::new(7, "send", sched::SchedClass::Normal { weight: 1024 });
    let ctx = SendContext::new(&task);
    let mut batch = Batch { imported: Vec::new(), published: Vec::new() };
    assert_eq!(send_batch(&ctx, BatchSpec { len: 3, flags: 0 }, &mut batch), Ok(3));
    assert_eq!(batch.imported, [0, 1, 2]);
    assert_eq!(batch.published, [(0, 16), (1, 16), (2, 16)]);
    assert_eq!(task.sigpending.load(Ordering::Acquire), 0);
}

struct PartialBatch { imported: Vec<u32>, published: Vec<(u32, u32)> }

impl BatchIo for PartialBatch {
    fn file(&mut self) -> KResult<Arc<vfs::File>> { Ok(netlink_file()) }
    fn import(&mut self, _index: u32, _mode: ImportMode) -> KResult<Message> { Err(Error::Eio) }
    fn import_envelope(&mut self, index: u32) -> KResult<Option<Message>> {
        self.imported.push(index);
        Ok(Some(Message { requested_len: 16, ..Message::default() }))
    }
    fn import_payload(&mut self, index: u32, message: &mut Message) -> KResult<()> {
        if index == 1 { return Err(Error::Efault); }
        message.payload = valid_netlink_payload(index);
        Ok(())
    }
    fn publish(&mut self, index: u32, len: u32) -> KResult<()> {
        self.published.push((index, len)); Ok(())
    }
}

#[test]
fn phased_batch_returns_completed_prefix_without_failed_copyout() {
    let _policy = unpoliced();
    let task = sched::Task::new(20, "send", sched::SchedClass::Normal { weight: 1024 });
    let ctx = SendContext::new(&task);
    let mut batch = PartialBatch { imported: Vec::new(), published: Vec::new() };
    assert_eq!(send_batch(&ctx, BatchSpec { len: 3, flags: 0 }, &mut batch), Ok(1));
    assert_eq!(batch.imported, [0, 1]);
    assert_eq!(batch.published, [(0, 16)]);
}

#[test]
fn sendmmsg_marks_every_nonfinal_entry_as_batched() {
    const CALLER: u32 = net::uapi::MSG_DONTWAIT as u32;
    assert_eq!(batch::entry_flags(CALLER, 0, 3), CALLER | batch::MSG_BATCH);
    assert_eq!(batch::entry_flags(CALLER, 1, 3), CALLER | batch::MSG_BATCH);
    assert_eq!(batch::entry_flags(CALLER, 2, 3), CALLER);
    assert_eq!(batch::entry_flags(CALLER, 0, 1), CALLER);
}

struct RestartBatch { imported: Vec<u32>, published: Vec<(u32, u32)>, fail_at: u32 }

impl BatchIo for RestartBatch {
    fn file(&mut self) -> KResult<Arc<vfs::File>> { Ok(netlink_file()) }
    fn import(&mut self, _index: u32, _mode: ImportMode) -> KResult<Message> { Err(Error::Eio) }
    fn import_envelope(&mut self, index: u32) -> KResult<Option<Message>> {
        self.imported.push(index);
        Ok(Some(Message { requested_len: 16, ..Message::default() }))
    }
    fn import_payload(&mut self, index: u32, message: &mut Message) -> KResult<()> {
        if index == self.fail_at { return Err(Error::Erestartsys); }
        message.payload = valid_netlink_payload(index);
        Ok(())
    }
    fn publish(&mut self, index: u32, len: u32) -> KResult<()> {
        self.published.push((index, len)); Ok(())
    }
}

#[test]
fn sendmmsg_returns_a_restart_error_before_any_completed_entry() {
    let _policy = unpoliced();
    let task = sched::Task::new(21, "send", sched::SchedClass::Normal { weight: 1024 });
    let mut io = RestartBatch { imported: Vec::new(), published: Vec::new(), fail_at: 0 };
    assert_eq!(send_batch(&SendContext::new(&task), BatchSpec { len: 2, flags: 0 }, &mut io),
        Err(Error::Erestartsys));
    assert_eq!(io.imported, [0]);
    assert!(io.published.is_empty());
}

#[test]
fn sendmmsg_keeps_the_completed_prefix_when_a_later_entry_restarts() {
    let _policy = unpoliced();
    let task = sched::Task::new(22, "send", sched::SchedClass::Normal { weight: 1024 });
    let mut io = RestartBatch { imported: Vec::new(), published: Vec::new(), fail_at: 1 };
    assert_eq!(send_batch(&SendContext::new(&task), BatchSpec { len: 3, flags: 0 }, &mut io), Ok(1));
    assert_eq!(io.imported, [0, 1]);
    assert_eq!(io.published, [(0, 16)]);
}

struct RegularBatch { target: Arc<vfs::File>, imported: bool }

impl BatchIo for RegularBatch {
    fn file(&mut self) -> KResult<Arc<vfs::File>> { Ok(self.target.clone()) }
    fn import(&mut self, _index: u32, _mode: ImportMode) -> KResult<Message> {
        self.imported = true;
        Ok(Message::default())
    }
    fn publish(&mut self, _index: u32, _len: u32) -> KResult<()> { Ok(()) }
}

#[test]
fn zero_batch_rejects_regular_file_before_message_import() {
    let task = sched::Task::new(10, "send", sched::SchedClass::Normal { weight: 1024 });
    let ctx = SendContext::new(&task);
    let mut io = RegularBatch { target: file(vfs::OpenFlags::O_RDWR), imported: false };
    assert_eq!(send_batch(&ctx, BatchSpec { len: 0, flags: 0 }, &mut io), Err(Error::Enotsock));
    assert!(!io.imported);
}

#[test]
fn oversized_batch_keeps_fd_validation_before_linux_cap() {
    let task = sched::Task::new(11, "send", sched::SchedClass::Normal { weight: 1024 });
    let ctx = SendContext::new(&task);
    let mut io = RegularBatch { target: file(vfs::OpenFlags::O_RDWR), imported: false };
    assert_eq!(send_batch(&ctx, BatchSpec { len: batch::UIO_MAXIOV + 1, flags: 0 }, &mut io),
        Err(Error::Enotsock));
    assert!(!io.imported);
}

#[test]
fn oversized_socket_batch_is_limited_to_linux_uio_maxiov() {
    let _policy = unpoliced();
    let task = sched::Task::new(12, "send", sched::SchedClass::Normal { weight: 1024 });
    let ctx = SendContext::new(&task);
    let mut io = Batch { imported: Vec::new(), published: Vec::new() };
    assert_eq!(send_batch(&ctx, BatchSpec { len: batch::UIO_MAXIOV + 1, flags: 0 }, &mut io),
        Ok(batch::UIO_MAXIOV));
    assert_eq!(io.imported.len(), batch::UIO_MAXIOV as usize);
    assert_eq!(io.published.len(), batch::UIO_MAXIOV as usize);
    assert_eq!(io.imported.last(), Some(&(batch::UIO_MAXIOV - 1)));
}
