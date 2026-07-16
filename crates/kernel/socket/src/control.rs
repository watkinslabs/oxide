use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use crate::{Error, KResult, Message, SendContext};

const SOL_SOCKET: i32 = 1;
const SCM_RIGHTS: i32 = 1;
const SCM_CREDENTIALS: i32 = 2;

pub(crate) struct Scm {
    files: Vec<Arc<vfs::File>>,
    creds: Option<net::sock::SenderCreds>,
}

pub(crate) enum UnixScm {
    Datagram {
        scm: Scm,
        queue: Arc<net::UnixDgramQueue>,
        sender: Option<net::UnixAddr>,
        address: net::UnixAddr,
    },
    Stream(Scm),
}

fn i32_at(bytes: &[u8], offset: usize) -> i32 {
    i32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_ne_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn credentials(data: &[u8], task: &sched::Task) -> KResult<net::sock::SenderCreds> {
    if data.len() != 12 { return Err(Error::Einval); }
    let pid = i32_at(data, 0);
    let uid = u32::from_ne_bytes(data[4..8].try_into().unwrap());
    let gid = u32::from_ne_bytes(data[8..12].try_into().unwrap());
    if pid <= 0 { return Err(Error::Esrch); }
    let pid_ok = pid == task.visible_pid() as i32 || task.has_cap(sched::cap::SYS_ADMIN);
    let uid_ok = uid == task.creds.ruid.load(Ordering::Acquire)
        || uid == task.creds.euid.load(Ordering::Acquire)
        || uid == task.creds.suid.load(Ordering::Acquire) || task.has_cap(sched::cap::SETUID);
    let gid_ok = gid == task.creds.rgid.load(Ordering::Acquire)
        || gid == task.creds.egid.load(Ordering::Acquire)
        || gid == task.creds.sgid.load(Ordering::Acquire) || task.has_cap(sched::cap::SETGID);
    if !pid_ok || !uid_ok || !gid_ok { return Err(Error::Eperm); }
    if pid != task.visible_pid() as i32 && sched::registry::resolve_user_pid(pid as u32).is_none() {
        return Err(Error::Esrch);
    }
    Ok(net::sock::SenderCreds { pid: pid as u32, uid, gid })
}

fn parse(ctx: &SendContext<'_>, control: &[u8], allow_rights: bool) -> KResult<Scm> {
    let mut files = Vec::new();
    let mut creds = None;
    let mut offset = 0usize;
    while control.len().saturating_sub(offset) >= crate::ids::CMSG_HEADER_LEN {
        let len = usize::try_from(u64_at(control, offset)).map_err(|_| Error::Einval)?;
        if len < crate::ids::CMSG_HEADER_LEN || len > control.len() - offset { return Err(Error::Einval); }
        let level = i32_at(control, offset + 8);
        let kind = i32_at(control, offset + 12);
        if level == SOL_SOCKET && kind == SCM_RIGHTS {
            if !allow_rights { return Err(Error::Einval); }
            let bytes = len - crate::ids::CMSG_HEADER_LEN;
            if bytes % 4 != 0 || files.len().saturating_add(bytes / 4) > crate::ids::SCM_MAX_FD {
                return Err(Error::Einval);
            }
            for at in (offset + crate::ids::CMSG_HEADER_LEN..offset + len).step_by(4) {
                // SAFETY: work caller passes the running task; its fd-table view is stable for this operation.
                let table = unsafe { ctx.task().fd_table_ref() }.ok_or(Error::Ebadf)?;
                let file = table.get(i32_at(control, at)).map_err(|_| Error::Ebadf)?;
                if file.inode().ino() & crate::ids::INO_TAG_MASK == crate::ids::IO_URING_INO_TAG { return Err(Error::Einval); }
                files.push(file);
            }
        } else if level == SOL_SOCKET && kind == SCM_CREDENTIALS {
            creds = Some(credentials(&control[offset + crate::ids::CMSG_HEADER_LEN..offset + len], ctx.task())?);
        } else if level == SOL_SOCKET { return Err(Error::Einval); }
        let aligned = len.checked_add(crate::ids::CMSG_ALIGN_MASK).ok_or(Error::Einval)? & !crate::ids::CMSG_ALIGN_MASK;
        let next = offset.checked_add(aligned).ok_or(Error::Einval)?;
        if next > control.len() { break; }
        offset = next;
    }
    Ok(Scm { files, creds })
}

/// Validate ancillary data for a non-AF_UNIX target. # C: O(control bytes)
pub(crate) fn validate_non_unix(ctx: &SendContext<'_>, control: &[u8]) -> KResult<()> {
    if control.is_empty() { return Ok(()); }
    parse(ctx, control, false).map(|_| ())
}

fn stream(_ctx: &SendContext<'_>, socket: &Arc<net::sock::InetSocket>, payload: &[u8],
    scm: &Scm, cap: usize, include_control: bool) -> KResult<usize>
{
    enum Target { Stream(Arc<net::UnixPair>, net::UnixEnd), Msg(Arc<net::UnixMsgPair>, net::UnixEnd) }
    let target = match &*socket.kind.lock() {
        net::sock::SockKind::Unix(pair, end) => Target::Stream(pair.clone(), *end),
        net::sock::SockKind::UnixMsgPair(pair, end) => Target::Msg(pair.clone(), *end),
        _ => return Err(Error::Einval),
    };
    let rights = net::classify_files(if include_control { scm.files.clone() } else { Vec::new() });
    let supplied = if include_control { scm.creds } else { None };
    let result = match target {
        Target::Stream(pair, end) => match supplied {
            Some(creds) => pair.write_with_rights_and_creds_bounded(end, payload, rights,
                (creds.pid, creds.uid, creds.gid), cap),
            None => pair.write_with_rights_bounded(end, payload, rights, cap),
        }.map_err(|error| match error {
            net::unix_sock::UnixStreamSendError::PeerClosed => Error::Epipe,
            net::unix_sock::UnixStreamSendError::WouldBlock => Error::Eagain,
        }),
        Target::Msg(pair, end) => match supplied {
            Some(creds) => pair.send_with_rights_and_creds_bounded(end, payload, rights,
                (creds.pid, creds.uid, creds.gid), cap),
            None => pair.send_with_rights_bounded(end, payload, rights, cap),
        }.map_err(|error| match error {
            net::unix_sock::UnixMsgSendError::PeerClosed => Error::Epipe,
            net::unix_sock::UnixMsgSendError::PeerRefused => Error::Econnrefused,
            net::unix_sock::UnixMsgSendError::WouldBlock => Error::Eagain,
            net::unix_sock::UnixMsgSendError::MessageTooLarge => Error::Emsgsize,
        }),
    };
    result
}

fn datagram(ctx: &SendContext<'_>, message: &Message, scm: &Scm,
    queue: Arc<net::UnixDgramQueue>, sender: Option<net::UnixAddr>, address: net::UnixAddr,
    cap: usize)
    -> KResult<usize>
{
    let creds = scm.creds.unwrap_or_else(|| ctx.creds());
    let datagram = net::UnixDgram { payload: message.payload.clone(),
        creds: (creds.pid, creds.uid, creds.gid), fds: Vec::new() };
    queue.try_push_from_with_rights_bounded(datagram, sender,
        net::classify_files(scm.files.clone()), cap)
        .map_err(Error::from)?;
    net::trace_dgram_journal(&address.display, &message.payload);
    Ok(message.payload.len())
}

/// Pin SCM objects and resolve AF_UNIX send state before payload import. # C: O(control + lookup)
pub(crate) fn prepare_unix(ctx: &SendContext<'_>, socket: &Arc<net::sock::InetSocket>,
    message: &Message) -> Option<KResult<UnixScm>>
{
    enum Kind { Datagram(Arc<net::UnixDgramQueue>), Stream }
    let kind = match &*socket.kind.lock() {
        net::sock::SockKind::UnixDgram(queue) => Kind::Datagram(queue.clone()),
        net::sock::SockKind::Unix(_, _) | net::sock::SockKind::UnixMsgPair(_, _) => Kind::Stream,
        _ => return None,
    };
    Some((|| {
        let scm = parse(ctx, &message.control, true)?;
        match kind {
            Kind::Stream => Ok(UnixScm::Stream(scm)),
            Kind::Datagram(local) => {
                if socket.write_shut.load(Ordering::Acquire) { return Err(Error::Epipe); }
                let sender = local.bound();
                let address = if let Some(name) = message.name.as_deref() {
                    crate::address::unix(ctx, name)?
                } else { local.peer().ok_or(Error::Edestaddrreq)? };
                let queue = net::net_ns::unix_registry_for_addr_in(&socket.net_namespace, &address)
                    .dgram_lookup_addr(&address).ok_or(Error::Econnrefused)?;
                Ok(UnixScm::Datagram { scm, queue, sender, address })
            }
        }
    })())
}

/// Commit one prepared AF_UNIX send transaction. # C: O(payload)
pub(crate) fn send_unix_once(ctx: &SendContext<'_>, socket: &Arc<net::sock::InetSocket>,
    message: &Message, scm: &UnixScm, cap: usize, offset: usize) -> KResult<usize>
{
    match scm {
        UnixScm::Datagram { scm, queue, sender, address } =>
            datagram(ctx, message, scm, queue.clone(), sender.clone(), address.clone(), cap),
        UnixScm::Stream(scm) => stream(ctx, socket, &message.payload[offset..], scm, cap, offset == 0),
    }
}

/// Arm the exact AF_UNIX destination queue selected during send preparation. # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn wait_unix_send(socket: &Arc<net::sock::InetSocket>, scm: &UnixScm,
    len: usize, cap: usize, deadline_ns: u64) -> KResult<()>
{
    match scm {
        UnixScm::Datagram { queue, .. } => match queue.arm_write(len, cap, deadline_ns) {
            net::unix_sock::dgram::ArmDgramWrite::Retry => Ok(()),
            net::unix_sock::dgram::ArmDgramWrite::PeerClosed => Err(Error::Econnrefused),
            net::unix_sock::dgram::ArmDgramWrite::MessageTooLarge => Err(Error::Emsgsize),
            net::unix_sock::dgram::ArmDgramWrite::Parked => {
                // SAFETY: queue armed current under its message lock.
                unsafe { sched::live::schedule::schedule(); }
                queue.writers.remove_current();
                Ok(())
            }
        },
        UnixScm::Stream(_) => {
            enum Target { Stream(Arc<net::UnixPair>, net::UnixEnd), Msg(Arc<net::UnixMsgPair>, net::UnixEnd) }
            let target = match &*socket.kind.lock() {
                net::sock::SockKind::Unix(pair, end) => Target::Stream(pair.clone(), *end),
                net::sock::SockKind::UnixMsgPair(pair, end) => Target::Msg(pair.clone(), *end),
                _ => return Err(Error::Einval),
            };
            match target {
                Target::Stream(pair, end) => match pair.arm_stream_write(end, cap, deadline_ns) {
                    net::unix_sock::stream::ArmStreamWrite::Retry => Ok(()),
                    net::unix_sock::stream::ArmStreamWrite::PeerClosed => Err(Error::Epipe),
                    net::unix_sock::stream::ArmStreamWrite::Parked => {
                        // SAFETY: pair armed current under its outgoing-ring lock.
                        unsafe { sched::live::schedule::schedule(); }
                        pair.writer_waiters(end).remove_current();
                        Ok(())
                    }
                },
                Target::Msg(pair, end) => match pair.arm_write(end, len, cap, deadline_ns) {
                    net::unix_sock::msg_pair::ArmMsgWrite::Retry => Ok(()),
                    net::unix_sock::msg_pair::ArmMsgWrite::PeerClosed => Err(Error::Epipe),
                    net::unix_sock::msg_pair::ArmMsgWrite::MessageTooLarge => Err(Error::Emsgsize),
                    net::unix_sock::msg_pair::ArmMsgWrite::Parked => {
                        // SAFETY: pair armed current under its outgoing-queue lock.
                        unsafe { sched::live::schedule::schedule(); }
                        pair.writer_waiters(end).remove_current();
                        Ok(())
                    }
                },
            }
        }
    }
}
