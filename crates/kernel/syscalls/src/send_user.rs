use alloc::sync::Arc;
use alloc::vec::Vec;

use syscall::errno::Errno;

use uaccess::MAX_RW_COUNT;

const MSGHDR_LEN: usize = 56;
const COMPAT_MSGHDR_LEN: usize = 28;
const IOVEC_LEN: usize = 16;
const COMPAT_IOVEC_LEN: usize = 8;
const UIO_MAXIOV: usize = 1024;
const SOCKADDR_STORAGE_LEN: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IoVec {
    base: u64,
    len: usize,
}

struct SendMeta {
    iov: Vec<IoVec>,
    control: u64,
    controllen: usize,
    name: Option<Vec<u8>>,
}

fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }

fn work_error(error: i64) -> socket::Error {
    if error == errno(Errno::Efault) { socket::Error::Efault }
    else if error == errno(Errno::Enomem) { socket::Error::Enomem }
    else if error == errno(Errno::Emsgsize) { socket::Error::Emsgsize }
    else if error == errno(Errno::Enobufs) { socket::Error::Enobufs }
    else if error == errno(Errno::Einval) { socket::Error::Einval }
    else { socket::Error::Eio }
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_ne_bytes(bytes[at..at + 4].try_into().unwrap())
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_ne_bytes(bytes[at..at + 8].try_into().unwrap())
}

fn copy_vec(src: u64, len: usize) -> Result<Vec<u8>, i64> {
    let mut out = Vec::new();
    out.try_reserve_exact(len).map_err(|_| errno(Errno::Enomem))?;
    out.resize(len, 0);
    if len != 0 { uaccess::copy_from_user(&mut out, src).map_err(errno)?; }
    Ok(out)
}

fn copy_sockaddr(src: u64, raw_len: u64) -> Result<Vec<u8>, i64> {
    let signed = raw_len as i32;
    if signed < 0 { return Err(errno(Errno::Einval)); }
    // Linux `__copy_msghdr` clamps an oversized `msg_namelen` to
    // sockaddr_storage rather than rejecting it (unlike `move_addr_to_kernel`
    // used by bind/sendto); the address parser reads only the family's struct.
    let len = core::cmp::min(signed as usize, SOCKADDR_STORAGE_LEN);
    copy_vec(src, len)
}

fn import_name_with<F>(src: u64, raw_len: u32, copy: F) -> Result<Option<Vec<u8>>, i64>
where F: FnOnce(u64, usize) -> Result<Vec<u8>, i64> {
    if src == 0 { return Ok(None); }
    let signed = raw_len as i32;
    if signed < 0 { return Err(errno(Errno::Einval)); }
    // Linux `__copy_msghdr` clamps `msg_namelen > sizeof(sockaddr_storage)`.
    let len = core::cmp::min(signed as usize, SOCKADDR_STORAGE_LEN);
    if len == 0 { Ok(None) } else { copy(src, len).map(Some) }
}

fn import_name_and_iovlen_with<F>(src: u64, raw_namelen: u32, raw_iovlen: u64,
    copy: F) -> Result<(Option<Vec<u8>>, usize), i64>
where F: FnOnce(u64, usize) -> Result<Vec<u8>, i64> {
    let name = import_name_with(src, raw_namelen, copy)?;
    let iovlen = usize::try_from(raw_iovlen).map_err(|_| errno(Errno::Emsgsize))?;
    if iovlen > UIO_MAXIOV { return Err(errno(Errno::Emsgsize)); }
    Ok((name, iovlen))
}

fn gather_with<F>(iov: &[IoVec], total: usize, mut copy: F) -> Result<(Vec<u8>, bool), i64>
where F: FnMut(*mut u8, u64, usize) -> usize {
    let mut out = Vec::new();
    out.try_reserve_exact(total).map_err(|_| errno(Errno::Enomem))?;
    out.resize(total, 0);
    let mut copied = 0usize;
    for entry in iov {
        if copied == total { break; }
        let take = core::cmp::min(entry.len, total - copied);
        if take == 0 { continue; }
        // SAFETY: copied is bounded by the initialized allocation's total length.
        let dst = unsafe { out.as_mut_ptr().add(copied) };
        let left = core::cmp::min(take, copy(dst, entry.base, take));
        copied += take - left;
        if left != 0 {
            out.truncate(copied);
            return if copied != 0 { Ok((out, true)) } else { Err(errno(Errno::Efault)) };
        }
    }
    out.truncate(copied);
    Ok((out, false))
}

fn gather(iov: &[IoVec], total: usize) -> Result<(Vec<u8>, bool), i64> {
    gather_with(iov, total, |dst, src, len| {
        // SAFETY: dst spans initialized Vec storage; raw usercopy recovers source faults.
        unsafe { uaccess::raw_copy_from_user(dst, src, len) }
    })
}

fn capped_total(iov: &[IoVec]) -> usize {
    let mut total = 0usize;
    for entry in iov {
        total = core::cmp::min(MAX_RW_COUNT, total.saturating_add(entry.len));
    }
    total
}

fn import_meta(msgp: u64) -> Result<SendMeta, i64> {
    let mut hdr = [0u8; MSGHDR_LEN];
    uaccess::copy_from_user(&mut hdr, msgp).map_err(errno)?;
    let name = u64_at(&hdr, 0);
    let namelen = u32_at(&hdr, 8);
    let iovp = u64_at(&hdr, 16);
    let raw_iovlen = u64_at(&hdr, 24);
    let control = u64_at(&hdr, 32);
    let raw_controllen = u64_at(&hdr, 40);

    let (name, iovlen) = import_name_and_iovlen_with(name, namelen, raw_iovlen, copy_vec)?;
    let bytes_len = iovlen.checked_mul(IOVEC_LEN).ok_or_else(|| errno(Errno::Emsgsize))?;
    let raw = copy_vec(iovp, bytes_len)?;
    let mut iov = Vec::with_capacity(iovlen);
    for entry in raw.chunks_exact(IOVEC_LEN) {
        let base = u64_at(entry, 0);
        let len = usize::try_from(u64_at(entry, 8)).map_err(|_| errno(Errno::Einval))?;
        if len != 0 && !uaccess::access_ok(base, len) { return Err(errno(Errno::Efault)); }
        iov.push(IoVec { base, len });
    }
    let controllen = usize::try_from(raw_controllen).map_err(|_| errno(Errno::Einval))?;
    if controllen > net::sysctl::optmem_max() { return Err(errno(Errno::Enobufs)); }

    Ok(SendMeta { iov, control, controllen, name })
}

fn import_meta_compat(msgp: u64) -> Result<SendMeta, i64> {
    let mut hdr = [0u8; COMPAT_MSGHDR_LEN];
    uaccess::copy_from_user(&mut hdr, msgp).map_err(errno)?;
    let name = u32_at(&hdr, 0) as u64;
    let namelen = u32_at(&hdr, 4);
    let iovp = u32_at(&hdr, 8) as u64;
    let raw_iovlen = u32_at(&hdr, 12) as u64;
    let control = u32_at(&hdr, 16) as u64;
    let controllen = u32_at(&hdr, 20) as usize;
    let (name, iovlen) = import_name_and_iovlen_with(name, namelen, raw_iovlen, copy_vec)?;
    let bytes_len = iovlen.checked_mul(COMPAT_IOVEC_LEN).ok_or_else(|| errno(Errno::Emsgsize))?;
    let raw = copy_vec(iovp, bytes_len)?;
    let mut iov = Vec::with_capacity(iovlen);
    for entry in raw.chunks_exact(COMPAT_IOVEC_LEN) {
        let base = u32_at(entry, 0) as u64;
        let len = u32_at(entry, 4) as usize;
        if len != 0 && !uaccess::access_ok(base, len) { return Err(errno(Errno::Efault)); }
        iov.push(IoVec { base, len });
    }
    if controllen > net::sysctl::optmem_max() { return Err(errno(Errno::Enobufs)); }
    Ok(SendMeta { iov, control, controllen, name })
}

/// Validate the send envelope and ancillary bytes without touching payload pages. # C: O(iovlen + name + control)
pub(crate) fn import_raw_oob(msgp: u64) -> Result<socket::Message, i64> {
    let meta = import_meta(msgp)?;
    let requested_len = capped_total(&meta.iov);
    let control = copy_vec(meta.control, meta.controllen)?;
    Ok(socket::Message { requested_len, control, name: meta.name, ..socket::Message::default() })
}

fn import_raw_oob_compat(msgp: u64) -> Result<socket::Message, i64> {
    let meta = import_meta_compat(msgp)?;
    let requested_len = capped_total(&meta.iov);
    let control = copy_vec(meta.control, meta.controllen)?;
    Ok(socket::Message { requested_len, control, name: meta.name, ..socket::Message::default() })
}

/// Import a native LP64 Linux msghdr, iovecs, and send-side byte buffers. # C: O(iovlen + bytes + faults)
pub(crate) fn import(msgp: u64) -> Result<socket::Message, i64> {
    let meta = import_meta(msgp)?;
    let requested_len = capped_total(&meta.iov);
    let (payload, payload_faulted) = match gather(&meta.iov, requested_len) {
        Ok(result) => result,
        Err(error) if error == errno(Errno::Efault) => (Vec::new(), true),
        Err(error) => return Err(error),
    };
    let control = copy_vec(meta.control, meta.controllen)?;
    Ok(socket::Message { payload, payload_faulted, requested_len, control, name: meta.name })
}

fn import_compat(msgp: u64) -> Result<socket::Message, i64> {
    let meta = import_meta_compat(msgp)?;
    let requested_len = capped_total(&meta.iov);
    let (payload, payload_faulted) = match gather(&meta.iov, requested_len) {
        Ok(result) => result,
        Err(error) if error == errno(Errno::Efault) => (Vec::new(), true),
        Err(error) => return Err(error),
    };
    let control = copy_vec(meta.control, meta.controllen)?;
    Ok(socket::Message { payload, payload_faulted, requested_len, control, name: meta.name })
}

fn import_envelope_at(msgp: u64) -> Result<(socket::Message, SendMeta), i64> {
    let mut meta = import_meta(msgp)?;
    let requested_len = capped_total(&meta.iov);
    let control = copy_vec(meta.control, meta.controllen)?;
    let name = meta.name.take();
    Ok((socket::Message { requested_len, control, name, ..socket::Message::default() }, meta))
}

fn import_payload_from(meta: SendMeta, message: &mut socket::Message) -> Result<(), i64> {
    match gather(&meta.iov, message.requested_len) {
        Ok((payload, faulted)) => {
            message.payload = payload;
            message.payload_faulted = faulted;
            Ok(())
        }
        Err(error) if error == errno(Errno::Efault) => {
            message.payload_faulted = true;
            Ok(())
        }
        Err(error) => Err(error),
    }
}

pub(crate) struct SendMsgIo<'a> {
    task: &'a sched::Task,
    fd: i32,
    source: u64,
    meta: Option<SendMeta>,
}

impl<'a> SendMsgIo<'a> {
    /// Build one native sendmsg importer over the retained task context. # C: O(1)
    pub(crate) fn new(task: &'a sched::Task, fd: i32, source: u64) -> Self {
        Self { task, fd, source, meta: None }
    }
}

impl socket::MessageIo for SendMsgIo<'_> {
    fn file(&mut self) -> socket::KResult<Arc<vfs::File>> {
        // SAFETY: running task on this CPU; preempt-off; fd-table view is stable for lookup.
        let table = unsafe { self.task.fd_table_ref() }.ok_or(socket::Error::Ebadf)?;
        table.get(self.fd).map_err(|_| socket::Error::Ebadf)
    }

    fn import(&mut self, mode: socket::ImportMode) -> socket::KResult<socket::Message> {
        match mode {
            socket::ImportMode::Full => import(self.source),
            socket::ImportMode::RawOobEnvelope => import_raw_oob(self.source),
        }.map_err(work_error)
    }

    fn import_envelope(&mut self) -> socket::KResult<Option<socket::Message>> {
        let (message, meta) = import_envelope_at(self.source).map_err(work_error)?;
        self.meta = Some(meta);
        Ok(Some(message))
    }

    fn import_payload(&mut self, message: &mut socket::Message) -> socket::KResult<()> {
        let meta = self.meta.take().ok_or(socket::Error::Eio)?;
        import_payload_from(meta, message).map_err(work_error)
    }
}

pub(crate) struct SendtoIo<'a> {
    task: &'a sched::Task,
    fd: i32,
    payload: u64,
    len: usize,
    name: u64,
    namelen: u64,
}

impl<'a> SendtoIo<'a> {
    /// Build one phased sendto importer over the retained task context. # C: O(1)
    pub(crate) fn new(task: &'a sched::Task, fd: i32, payload: u64, len: usize,
        name: u64, namelen: u64) -> Self
    {
        Self { task, fd, payload, len, name, namelen }
    }
}

impl socket::MessageIo for SendtoIo<'_> {
    fn file(&mut self) -> socket::KResult<Arc<vfs::File>> {
        // SAFETY: running task on this CPU; preempt-off; fd-table view is stable for lookup.
        let table = unsafe { self.task.fd_table_ref() }.ok_or(socket::Error::Ebadf)?;
        table.get(self.fd).map_err(|_| socket::Error::Ebadf)
    }

    fn import_envelope(&mut self) -> socket::KResult<Option<socket::Message>> {
        let name = if self.name == 0 { None } else {
            Some(copy_sockaddr(self.name, self.namelen).map_err(work_error)?)
        };
        Ok(Some(socket::Message { requested_len: self.len, name,
            ..socket::Message::default() }))
    }

    fn import_payload(&mut self, message: &mut socket::Message) -> socket::KResult<()> {
        message.payload = copy_vec(self.payload, self.len).map_err(work_error)?;
        Ok(())
    }

    fn import(&mut self, mode: socket::ImportMode) -> socket::KResult<socket::Message> {
        if mode == socket::ImportMode::RawOobEnvelope {
            return Ok(socket::Message { requested_len: self.len, ..socket::Message::default() });
        }
        let name = if self.name == 0 { None } else {
            Some(copy_sockaddr(self.name, self.namelen).map_err(work_error)?)
        };
        let payload = copy_vec(self.payload, self.len).map_err(work_error)?;
        Ok(socket::Message { payload, requested_len: self.len, name, ..socket::Message::default() })
    }
}

const MMSGHDR_LEN: u64 = 64;
const MSG_LEN_OFFSET: u64 = 56;
const COMPAT_MMSGHDR_LEN: u64 = 32;
const COMPAT_MMSG_LEN_OFFSET: u64 = 28;

pub(crate) struct SendBatchIo<'a> {
    task: &'a sched::Task,
    fd: i32,
    base: u64,
    meta: Option<(u32, SendMeta)>,
    compat: bool,
}

impl<'a> SendBatchIo<'a> {
    /// Build one lazy sendmmsg importer over the retained task context. # C: O(1)
    pub(crate) fn new(task: &'a sched::Task, fd: i32, base: u64) -> Self {
        Self { task, fd, base, meta: None, compat: false }
    }

    fn entry(&self, index: u32) -> socket::KResult<u64> {
        let stride = if self.compat { COMPAT_MMSGHDR_LEN } else { MMSGHDR_LEN };
        let offset = (index as u64).checked_mul(stride).ok_or(socket::Error::Efault)?;
        self.base.checked_add(offset).ok_or(socket::Error::Efault)
    }
}

impl socket::BatchIo for SendBatchIo<'_> {
    fn file(&mut self) -> socket::KResult<Arc<vfs::File>> {
        // SAFETY: running task on this CPU; preempt-off; fd-table view is stable for lookup.
        let table = unsafe { self.task.fd_table_ref() }.ok_or(socket::Error::Ebadf)?;
        table.get(self.fd).map_err(|_| socket::Error::Ebadf)
    }

    fn import(&mut self, index: u32, mode: socket::ImportMode) -> socket::KResult<socket::Message> {
        let entry = self.entry(index)?;
        match mode {
            socket::ImportMode::Full => if self.compat { import_compat(entry) } else { import(entry) },
            socket::ImportMode::RawOobEnvelope => if self.compat {
                import_raw_oob_compat(entry)
            } else { import_raw_oob(entry) },
        }.map_err(work_error)
    }

    fn import_envelope(&mut self, index: u32) -> socket::KResult<Option<socket::Message>> {
        let entry = self.entry(index)?;
        let (message, meta) = if self.compat {
            let mut meta = import_meta_compat(entry).map_err(work_error)?;
            let requested_len = capped_total(&meta.iov);
            let control = copy_vec(meta.control, meta.controllen).map_err(work_error)?;
            let name = meta.name.take();
            (socket::Message { requested_len, control, name, ..socket::Message::default() }, meta)
        } else { import_envelope_at(entry).map_err(work_error)? };
        self.meta = Some((index, meta));
        Ok(Some(message))
    }

    fn import_payload(&mut self, index: u32, message: &mut socket::Message)
        -> socket::KResult<()>
    {
        let (entry, meta) = self.meta.take().ok_or(socket::Error::Eio)?;
        if entry != index { return Err(socket::Error::Eio); }
        import_payload_from(meta, message).map_err(work_error)
    }

    fn publish(&mut self, index: u32, len: u32) -> socket::KResult<()> {
        let offset = if self.compat { COMPAT_MMSG_LEN_OFFSET } else { MSG_LEN_OFFSET };
        let destination = self.entry(index)?.checked_add(offset).ok_or(socket::Error::Efault)?;
        uaccess::copy_to_user(destination, &len.to_ne_bytes()).map_err(|error| {
            work_error(errno(error))
        })
    }
}

#[cfg(test)]
#[path = "send_user/tests.rs"]
mod tests;
