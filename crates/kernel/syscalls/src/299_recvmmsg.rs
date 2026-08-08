// `sys_recvmmsg` — slot 299. ABI only: import one entry, run one receive,
// publish one length. Every batch DECISION — what admits a batch, what ends
// one, what a partly-delivered batch reports, and the order those questions
// are asked in — belongs to `crate::mmsg_batch`, which is ungated and
// therefore tested. This file implements `mmsg_batch::BatchOps` and does no
// more than the trait's one-step-each contract.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use net::uapi::MSG_OOB;

use crate::mmsg_batch::{self, BatchOps};
use crate::msg_layout::{EntryAbi, MsgLayout, TIMESPEC_SIZE};
use crate::recvmsg::dispatch::RecvTarget;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

struct BatchTimeout {
    user: u64,
    deadline: u64,
    remaining: u64,
}

/// One batch's ABI state: the raw arguments, the supplied timeout, and the
/// one socket the whole batch receives from.
struct Batch {
    fd: u64,
    mmsg: u64,
    timeout_user: u64,
    timeout: Option<BatchTimeout>,
    target: Option<RecvTarget>,
    /// Settled by the batch runner before any entry is touched; every stride
    /// and offset below comes from it.
    layout: MsgLayout,
}

impl Batch {
    /// Address of entry `index`, or `EFAULT` when the array would wrap.
    /// # C: O(1)
    fn entry(&self, index: u64) -> Result<u64, i64> {
        index.checked_mul(self.layout.mmsghdr_size()).and_then(|off| self.mmsg.checked_add(off))
            .ok_or(err(Errno::Efault))
    }

    /// # C: O(1)
    fn target(&self) -> &RecvTarget {
        self.target.as_ref().expect("resolve runs before any entry")
    }
}

impl BatchOps for Batch {
    fn use_layout(&mut self, layout: MsgLayout) { self.layout = layout; }

    fn import_timeout(&mut self) -> Result<(), i64> {
        if self.timeout_user == 0 { return Ok(()); }
        let mut raw = [0u8; TIMESPEC_SIZE];
        uaccess::copy_from_user(&mut raw, self.timeout_user).map_err(|_| err(Errno::Efault))?;
        let sec = i64::from_ne_bytes(raw[..8].try_into().unwrap());
        let nsec = i64::from_ne_bytes(raw[8..].try_into().unwrap());
        let total = mmsg_batch::timeout_total_ns(sec, nsec).map_err(err)?;
        let now = crate::time_common::monotonic_ns();
        self.timeout = Some(BatchTimeout { user: self.timeout_user,
            deadline: now.saturating_add(total), remaining: total });
        Ok(())
    }

    fn resolve(&mut self) -> Result<(), i64> {
        self.target = Some(crate::recvmsg::lookup(self.fd)?);
        Ok(())
    }

    fn take_pending_error(&mut self) -> i32 { self.target().take_error() }

    fn receive(&mut self, index: u64, flags: u64) -> i64 {
        let entry = match self.entry(index) { Ok(entry) => entry, Err(e) => return e };
        let user = match crate::recv_user::import(entry, self.layout) {
            Ok(user) => user, Err(e) => return e };
        crate::recvmsg::recv(self.target(), &user, flags)
    }

    fn publish(&mut self, index: u64, len: i64) -> Result<(), i64> {
        let len_ptr = self.entry(index)?.checked_add(self.layout.mmsghdr_len_offset())
            .ok_or(err(Errno::Efault))?;
        uaccess::copy_to_user(len_ptr, &(len as u32).to_ne_bytes()).map_err(|_| err(Errno::Efault))
    }

    fn received_oob(&mut self, index: u64) -> bool {
        let Ok(entry) = self.entry(index) else { return false };
        let Some(flags_ptr) = entry.checked_add(self.layout.mmsghdr_flags_offset())
            else { return false };
        let mut raw = [0u8; 4];
        if uaccess::copy_from_user(&mut raw, flags_ptr).is_err() { return false; }
        u32::from_ne_bytes(raw) as u64 & MSG_OOB != 0
    }

    fn timeout_left(&mut self) -> Option<u64> {
        let timeout = self.timeout.as_mut()?;
        timeout.remaining = timeout.deadline.saturating_sub(crate::time_common::monotonic_ns());
        Some(timeout.remaining)
    }

    fn latch_error(&mut self, errno: i32) { self.target().set_pending_error(errno); }

    fn copy_timeout_back(&mut self) -> Result<(), i64> {
        let Some(timeout) = self.timeout.as_ref() else { return Ok(()) };
        let sec = timeout.remaining / crate::time_common::NS_PER_SEC;
        let nsec = timeout.remaining % crate::time_common::NS_PER_SEC;
        let mut raw = [0u8; TIMESPEC_SIZE];
        raw[..8].copy_from_slice(&(sec as i64).to_ne_bytes());
        raw[8..].copy_from_slice(&(nsec as i64).to_ne_bytes());
        uaccess::copy_to_user(timeout.user, &raw).map_err(|_| err(Errno::Efault))
    }
}

/// `recvmmsg(fd, mmsghdr*, vlen, flags, timeout)` — slot 299.
/// # C: O(vlen)
pub fn sys_recvmmsg(args: &SyscallArgs) -> i64 {
    let mut batch = Batch { fd: args.a0, mmsg: args.a1, timeout_user: args.a4,
        timeout: None, target: None, layout: MsgLayout::Native };
    mmsg_batch::run_batch(&mut batch, args.a3, args.a2, EntryAbi::Native)
}
