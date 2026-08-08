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
        /// Linux `unix_peer(other) == sk`: a symmetrically connected pair is
        /// NOT flow-controlled by the destination's receive queue, on the send
        /// side any more than in `poll`.
        symmetric: bool,
        /// The SENDING socket's own queue — Linux's `sk`, whose
        /// `sk_wmem_alloc` this send is charged against.
        local: Arc<net::UnixDgramQueue>,
    },
    Stream(Scm),
}

fn i32_at(bytes: &[u8], offset: usize) -> i32 {
    i32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap())
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
    for item in crate::cmsg_walk::CmsgWalk::new(control) {
        let item = item?;
        if item.level != SOL_SOCKET { continue; }
        match item.kind {
            SCM_RIGHTS => {
                // Descriptors ride only an AF_UNIX message; every other family
                // that runs this parser refuses the type outright.
                if !allow_rights { return Err(Error::Einval); }
                let count = item.data.len() / 4;
                if count > crate::ids::SCM_MAX_FD
                    || files.len().saturating_add(count) > crate::ids::SCM_MAX_FD
                { return Err(Error::Einval); }
                for slot in item.data.chunks_exact(4) {
                    // SAFETY: work caller passes the running task; its fd-table view is stable for this operation.
                    let table = unsafe { ctx.task().fd_table_ref() }.ok_or(Error::Ebadf)?;
                    let file = table.get(i32::from_ne_bytes(slot.try_into().unwrap()))
                        .map_err(|_| Error::Ebadf)?;
                    // An io_uring ring may not travel over SCM_RIGHTS. Which file
                    // is a ring is Linux `io_is_uring_fops` — a comparison against
                    // the vtable io_uring installs. This site used to carry its own
                    // COPY of io_uring's inode-number tag, a second source of truth
                    // for a number that proves no ownership anyway.
                    if file.inode().i_fop().is_io_uring() { return Err(Error::Einval); }
                    files.push(file);
                }
            }
            SCM_CREDENTIALS => creds = Some(credentials(item.data, ctx.task())?),
            _ => return Err(Error::Einval),
        }
    }
    Ok(Scm { files, creds })
}

/// Validate ancillary data for a target whose family speaks the SCM rule but
/// carries no descriptors — NETLINK. # C: O(control bytes)
pub(crate) fn validate_scm_no_rights(ctx: &SendContext<'_>, control: &[u8]) -> KResult<()> {
    if control.is_empty() { return Ok(()); }
    parse(ctx, control, false).map(|_| ())
}

fn stream(_ctx: &SendContext<'_>, socket: &Arc<net::sock::InetSocket>, payload: &[u8],
    scm: &Scm, cap: usize, include_control: bool, oob: bool) -> KResult<usize>
{
    enum Target { Stream(Arc<net::UnixPair>, net::UnixEnd), Msg(Arc<net::UnixMsgPair>, net::UnixEnd) }
    let target = match &*socket.kind.lock() {
        net::sock::SockKind::Unix(pair, end) => Target::Stream(pair.clone(), *end),
        net::sock::SockKind::UnixMsgPair(pair, end) => Target::Msg(pair.clone(), *end),
        _ => return Err(Error::Einval),
    };
    let rights = net::classify_files(if include_control { scm.files.clone() } else { Vec::new() });
    let supplied = if include_control { scm.creds } else { None };
    if oob {
        let Target::Stream(pair, end) = target else { return Err(Error::Eopnotsupp) };
        let byte = *payload.first().ok_or(Error::Eopnotsupp)?;
        let creds = supplied.map(|c| (c.pid, c.uid, c.gid));
        return pair.write_oob(end, byte, rights, creds, cap).map_err(|error| match error {
            net::unix_sock::UnixStreamSendError::PeerClosed => Error::Epipe,
            net::unix_sock::UnixStreamSendError::WouldBlock => Error::Eagain,
        });
    }
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
    cap: usize, local: &Arc<net::UnixDgramQueue>, sndbuf: usize)
    -> KResult<usize>
{
    let creds = scm.creds.unwrap_or_else(|| ctx.creds());
    let datagram = net::UnixDgram { payload: message.payload.clone(),
        creds: creds.stamp(), fds: Vec::new() };
    // `sock_alloc_send_pskb` + `skb_set_owner_w`: the sender's own write memory
    // is charged and bounds this send, which is the ONLY bound a symmetrically
    // connected pair has (`unix_dgram_sendmsg` skips the peer recvq test there).
    queue.try_push_owned(datagram, sender,
        net::classify_files(scm.files.clone()), cap, local, sndbuf)
        .map_err(Error::from)?;
    net::trace_dgram_journal(&address.display, &message.payload);
    Ok(message.payload.len())
}

/// Pin SCM objects and resolve AF_UNIX send state before payload import. # C: O(control + lookup)
pub(crate) fn prepare_unix(ctx: &SendContext<'_>, socket: &Arc<net::sock::InetSocket>,
    message: &Message, flags: u32) -> Option<KResult<UnixScm>>
{
    enum Kind { Datagram(Arc<net::UnixDgramQueue>), Stream, Unconnected }
    // Every SOCK_STREAM flavour, connected or not: they share the out-of-band
    // division and the rule that a destination address is not theirs to take.
    let byte_stream = matches!(*socket.kind.lock(), net::sock::SockKind::Unix(_, _)
        | net::sock::SockKind::UnixUnbound(_, _) | net::sock::SockKind::UnixListener(_));
    let connected = matches!(*socket.kind.lock(), net::sock::SockKind::Unix(_, _));
    let kind = match &*socket.kind.lock() {
        net::sock::SockKind::UnixDgram(queue) => Kind::Datagram(queue.clone()),
        net::sock::SockKind::Unix(_, _) | net::sock::SockKind::UnixMsgPair(_, _) => Kind::Stream,
        net::sock::SockKind::UnixUnbound(_, _) | net::sock::SockKind::UnixListener(_) =>
            Kind::Unconnected,
        _ => return None,
    };
    Some((|| {
        // Ancillary data is parsed FIRST: a malformed control buffer outranks
        // the absent out-of-band channel, whichever socket kind this is.
        let scm = parse(ctx, &message.control, true)?;
        let oob = flags as u64 & net::uapi::MSG_OOB != 0;
        if crate::oob::unix_oob_plan(byte_stream, oob, message.requested_len)
            == crate::oob::UnixOobPlan::Unsupported
        { return Err(Error::Eopnotsupp); }
        // A byte stream refuses a destination outright, and the refusal names
        // the connection state. A seqpacket send discards `msg_namelen`
        // instead and never looks, which is why only the stream kinds ask.
        if byte_stream && message.name.is_some() {
            return Err(if connected { Error::Eisconn } else { Error::Eopnotsupp });
        }
        match kind {
            // No peer was ever published, so there is nothing to send to.
            Kind::Unconnected => Err(Error::Enotconn),
            Kind::Stream => Ok(UnixScm::Stream(scm)),
            Kind::Datagram(local) => {
                if socket.write_shut.load(Ordering::Acquire) { return Err(Error::Epipe); }
                let sender = local.bound();
                let address = if let Some(name) = message.name.as_deref() {
                    crate::address::unix(ctx, name)?
                } else {
                    // No name and no peer: the datagram socket is not
                    // connected, which is the answer — not "a destination is
                    // required", which is what a socket that COULD take one
                    // would say.
                    local.peer().ok_or(Error::Enotconn)?
                };
                let queue = net::net_ns::unix_registry_for_addr_in(&socket.net_namespace, &address)
                    .dgram_lookup_addr(&address).ok_or(Error::Econnrefused)?;
                let symmetric = net::unix_sock::dgram_symmetric_pair(
                    queue.peer().as_ref(), local.bound().as_ref());
                Ok(UnixScm::Datagram { scm, queue, sender, address, symmetric, local })
            }
        }
    })())
}

/// Commit one prepared AF_UNIX send transaction. # C: O(payload)
pub(crate) fn send_unix_once(ctx: &SendContext<'_>, socket: &Arc<net::sock::InetSocket>,
    message: &Message, scm: &UnixScm, cap: usize, offset: usize, body: usize, oob: bool)
    -> KResult<usize>
{
    match scm {
        // `cap` is the sender's SO_SNDBUF. It serves two distinct Linux roles:
        // the destination's receive-queue bound (skipped when symmetric) and
        // the sender's own `sk_wmem_alloc` watermark (never skipped).
        UnixScm::Datagram { scm, queue, sender, address, symmetric, local } =>
            datagram(ctx, message, scm, queue.clone(), sender.clone(), address.clone(),
                if *symmetric { usize::MAX } else { cap }, local, cap),
        // The out-of-band tail is the payload's LAST byte; the body loop stops
        // one short of it and this step queues it as the urgent record.
        UnixScm::Stream(scm) if oob =>
            stream(ctx, socket, &message.payload[body..], scm, cap, offset == 0, true),
        UnixScm::Stream(scm) =>
            stream(ctx, socket, &message.payload[offset..body], scm, cap, offset == 0, false),
    }
}

/// Arm the exact AF_UNIX destination queue selected during send preparation. # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn wait_unix_send(socket: &Arc<net::sock::InetSocket>, scm: &UnixScm,
    len: usize, cap: usize, deadline_ns: u64) -> KResult<()>
{
    match scm {
        // The sender's own `sk_wmem_alloc` is checked FIRST and parks on the
        // SENDER's write-space list: for a symmetric pair it is the only bound,
        // so parking on the destination's receive queue would spin instead.
        UnixScm::Datagram { queue, symmetric, local, .. } => {
            if let net::unix_sock::dgram::ArmDgramWrite::Parked =
                local.arm_write_wmem(len, cap, deadline_ns)
            {
                // SAFETY: local armed current under its own message lock.
                unsafe { sched::live::schedule::schedule(); }
                local.writers.remove_current();
                return Ok(());
            }
            match queue.arm_write(len, if *symmetric { usize::MAX } else { cap }, deadline_ns) {
            net::unix_sock::dgram::ArmDgramWrite::Retry => Ok(()),
            net::unix_sock::dgram::ArmDgramWrite::PeerClosed => Err(Error::Econnrefused),
            net::unix_sock::dgram::ArmDgramWrite::MessageTooLarge => Err(Error::Emsgsize),
            net::unix_sock::dgram::ArmDgramWrite::Parked => {
                // SAFETY: queue armed current under its message lock.
                unsafe { sched::live::schedule::schedule(); }
                queue.writers.remove_current();
                Ok(())
            }
        }},
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
