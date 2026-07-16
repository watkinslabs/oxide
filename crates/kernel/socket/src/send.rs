use alloc::sync::Arc;
#[cfg(target_os = "oxide-kernel")]
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use sched::signum::Signum;

use crate::{Error, KResult, Message, SendFile, SendKind, SendOutcome};

type ResolvedAddress = ();

/// Construct the private unresolved-address marker. # C: O(1)
pub(crate) fn unresolved_address() -> ResolvedAddress {
    ()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImportMode {
    Full,
    RawOobEnvelope,
}

pub trait MessageIo {
    /// Fetch one open file description for this send. # C: O(1)
    fn file(&mut self) -> KResult<Arc<vfs::File>>;
    /// Import the selected user message data into kernel-owned memory. # C: O(message bytes)
    fn import(&mut self, mode: ImportMode) -> KResult<Message>;
    /// Import metadata, name, and control before payload pages, or select single-phase import. # C: O(envelope)
    fn import_envelope(&mut self) -> KResult<Option<Message>> { Ok(None) }
    /// Complete payload import after target-specific envelope preparation. # C: O(payload)
    fn import_payload(&mut self, _message: &mut Message) -> KResult<()> { Err(Error::Eio) }
}

pub struct SendContext<'a> {
    task: &'a sched::Task,
}

impl<'a> SendContext<'a> {
    /// Capture explicit task state needed by socket send policy. # C: O(1)
    pub fn new(task: &'a sched::Task) -> Self { Self { task } }

    /// Snapshot sender credentials from the retained task context. # C: O(1)
    pub(crate) fn creds(&self) -> net::sock::SenderCreds {
        net::sock::SenderCreds {
            pid: self.task.visible_pid(),
            uid: self.task.creds.euid.load(Ordering::Acquire),
            gid: self.task.creds.egid.load(Ordering::Acquire),
        }
    }

    /// Borrow the retained sender task context. # C: O(1)
    pub(crate) fn task(&self) -> &sched::Task { self.task }
}

/// Apply shared stream SIGPIPE completion semantics. # C: O(1)
pub(crate) fn complete(ctx: &SendContext<'_>, flags: u32, result: KResult<usize>) -> KResult<usize> {
    if result == Err(Error::Epipe) && flags & net::uapi::MSG_NOSIGNAL as u32 == 0 {
        ctx.task.sigpending.fetch_or(Signum::Sigpipe.bit(), Ordering::Release);
    }
    result
}

/// Write one kernel-owned byte slice through a retained file. # C: backend-dependent
pub fn write(ctx: &SendContext<'_>, file: Arc<vfs::File>, payload: &[u8]) -> KResult<usize> {
    let target = SendFile::new(file);
    #[cfg(target_os = "oxide-kernel")]
    if matches!(target.kind(), SendKind::Inet(socket) if matches!(*socket.kind.lock(),
        net::sock::SockKind::Unix(_, _) | net::sock::SockKind::UnixMsgPair(_, _)
            | net::sock::SockKind::UnixDgram(_)))
    {
        let message = Message { payload: payload.to_vec(), requested_len: payload.len(), ..Message::default() };
        return send_retained(ctx, &target, message, 0, unresolved_address()).map(|out| out.bytes);
    }
    let result = target.file().write(payload).map_err(Error::from);
    complete(ctx, 0, result)
}

/// Write one kernel-owned iterator through a retained file. # C: backend-dependent
pub fn writev(ctx: &SendContext<'_>, file: Arc<vfs::File>, bufs: &[&[u8]]) -> KResult<usize> {
    let target = SendFile::new(file);
    #[cfg(target_os = "oxide-kernel")]
    if matches!(target.kind(), SendKind::Inet(socket) if matches!(*socket.kind.lock(),
        net::sock::SockKind::Unix(_, _) | net::sock::SockKind::UnixMsgPair(_, _)
            | net::sock::SockKind::UnixDgram(_)))
    {
        let len = bufs.iter().try_fold(0usize, |sum, buf| sum.checked_add(buf.len())).ok_or(Error::Einval)?;
        let mut payload = Vec::new();
        payload.try_reserve_exact(len).map_err(|_| Error::Enomem)?;
        for buf in bufs { payload.extend_from_slice(buf); }
        let message = Message { payload, requested_len: len, ..Message::default() };
        return send_retained(ctx, &target, message, 0, unresolved_address()).map(|out| out.bytes);
    }
    let result = target.file().write_iter(bufs).map_err(Error::from);
    complete(ctx, 0, result)
}

fn family(name: &[u8]) -> KResult<u16> {
    if name.len() < 2 { return Err(Error::Einval); }
    Ok(u16::from_ne_bytes(name[..2].try_into().unwrap()))
}

fn netlink_address(message: &Message) -> KResult<(u32, u32)> {
    let (groups, pid) = if message.name.is_none() { (0, 0) } else {
        let name = message.name.as_deref().unwrap();
        if name.len() < 12 { return Err(Error::Einval); }
        if family(name)? != netlink::AF_NETLINK { return Err(Error::Eafnosupport); }
        (u32::from_ne_bytes(name[8..12].try_into().unwrap()),
            u32::from_ne_bytes(name[4..8].try_into().unwrap()))
    };
    Ok((groups, pid))
}

fn send_netlink(socket: &netlink::NetlinkSocket, message: &Message, groups: u32, pid: u32)
    -> KResult<usize>
{
    socket.send_to(&message.payload, groups, pid).map_err(Error::from)
}

pub(crate) enum InetPrepared {
    Packet,
    Unix(crate::control::UnixScm),
    Transport(crate::address::InetAddress, net::send_control::SendControl),
}

pub(crate) enum PreparedSend {
    Netlink { groups: u32, pid: u32 },
    Vsock,
    Inet(InetPrepared),
}

/// Validate family policy and retain backend state before payload import. # C: backend-dependent
pub(crate) fn prepare(ctx: &SendContext<'_>, target: &SendFile, message: &Message, flags: u32)
    -> KResult<PreparedSend>
{
    match target.kind() {
        SendKind::File => Err(Error::Enotsock),
        SendKind::Netlink(socket) => {
            if flags as u64 & net::uapi::MSG_OOB != 0 { return Err(Error::Eopnotsupp); }
            if message.requested_len == 0 { return Err(Error::Enodata); }
            crate::control::validate_non_unix(ctx, &message.control)?;
            let (groups, pid) = netlink_address(message)?;
            socket.preflight_send(message.requested_len).map_err(Error::from)?;
            Ok(PreparedSend::Netlink { groups, pid })
        }
        SendKind::Vsock(socket) => {
            if message.name.is_some() {
                return if matches!(*socket.kind.lock(), net::vsock_socket::VsockKind::Conn(_)) {
                    Err(Error::Eisconn)
                } else { Err(Error::Eopnotsupp) };
            }
            crate::control::validate_non_unix(ctx, &message.control)?;
            Ok(PreparedSend::Vsock)
        }
        SendKind::Inet(socket) => {
            if let Some(result) = crate::control::prepare_unix(ctx, socket, message) {
                return result.map(|scm| PreparedSend::Inet(InetPrepared::Unix(scm)));
            }
            if matches!(*socket.kind.lock(), net::sock::SockKind::Packet { .. }) {
                crate::packet::validate(message.name.as_deref())?;
                crate::control::validate_non_unix(ctx, &message.control)?;
                return Ok(PreparedSend::Inet(InetPrepared::Packet));
            }
            let address = crate::address::inet(message.name.as_deref())?;
            let raw_family = match &*socket.kind.lock() {
                net::sock::SockKind::Raw4(_) => Some(false),
                net::sock::SockKind::Raw6(_) => Some(true),
                _ => None,
            };
            crate::control::validate_non_unix(ctx, &message.control)?;
            let mut control = if let Some(ipv6) = raw_family {
                let cap = nscg::proc_ns::has_net_raw_for(ctx.task(), &socket.net_namespace);
                crate::control_raw::parse_raw_control(&message.control, ipv6, cap)?
            } else { net::send_control::SendControl::default() };
            control.apply_flags(flags as u64);
            Ok(PreparedSend::Inet(InetPrepared::Transport(address, control)))
        }
    }
}

#[cfg(target_os = "oxide-kernel")]
fn monotonic_ns() -> u64 {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
}

#[cfg(target_os = "oxide-kernel")]
fn send_inet(ctx: &SendContext<'_>, target: &SendFile, socket: &Arc<net::sock::InetSocket>,
    message: &Message, flags: u32, prepared: InetPrepared) -> KResult<usize>
{
    let (dest, control) = match prepared {
        InetPrepared::Packet =>
            return crate::packet::send(socket, &message.payload, message.name.as_deref()),
        InetPrepared::Unix(scm) =>
            return send_unix_blocking(ctx, target, socket, message, flags, scm),
        InetPrepared::Transport(address, control) => (address.remote(), control),
    };
    let nonblock = target.nonblock() || flags as u64 & net::uapi::MSG_DONTWAIT != 0;
    let signals_pipe = match &*socket.kind.lock() {
        net::sock::SockKind::Unix(_, _) | net::sock::SockKind::TcpConn(_) => true,
        net::sock::SockKind::UnixMsgPair(pair, _) => pair.kind == net::UnixMsgKind::SeqPacket,
        _ => false,
    };
    let deadline = {
        let timeout = socket.opts.sndtimeo_ns.load(Ordering::Acquire);
        if timeout > 0 { monotonic_ns().saturating_add(timeout as u64) } else { 0 }
    };
    let stream = matches!(&*socket.kind.lock(), net::sock::SockKind::TcpConn(_));
    let mut total = 0usize;
    loop {
        match net::sock::sendto(socket, &message.payload[total..], dest.clone(), ctx.creds(), &control) {
            Ok(bytes) if stream && bytes != 0 => {
                total += bytes;
                if total >= message.payload.len() { return Ok(total); }
            }
            Ok(bytes) => return Ok(total.saturating_add(bytes)),
            Err(net::NetError::Eagain) if nonblock => {
                return if total != 0 { Ok(total) } else { Err(Error::Eagain) };
            }
            Err(net::NetError::Eagain) => {
                if sched::live::deliverable_signals_self() != 0 {
                    return if total != 0 { Ok(total) } else { Err(Error::Eintr) };
                }
                if deadline != 0 && monotonic_ns() >= deadline {
                    return if total != 0 { Ok(total) } else { Err(Error::Eagain) };
                }
                if !net::sock::wait_transmit(socket, deadline) {
                    return if total != 0 { Ok(total) } else { Err(Error::Eagain) };
                }
            }
            Err(error) => {
                if total != 0 { return Ok(total); }
                let result = Err(Error::from(error));
                return if signals_pipe { complete(ctx, flags, result) } else { result };
            }
        }
    }
}

#[cfg(target_os = "oxide-kernel")]
fn send_unix_blocking(ctx: &SendContext<'_>, target: &SendFile,
    socket: &Arc<net::sock::InetSocket>, message: &Message, flags: u32,
    scm: crate::control::UnixScm) -> KResult<usize>
{
    let nonblock = target.nonblock() || flags as u64 & net::uapi::MSG_DONTWAIT != 0;
    let timeout = socket.opts.sndtimeo_ns.load(Ordering::Acquire);
    let deadline = if timeout > 0 { monotonic_ns().saturating_add(timeout as u64) } else { 0 };
    let cap = socket.opts.sndbuf.load(Ordering::Acquire).max(net::sock::TCP_SNDBUF_DEFAULT) as usize;
    let stream = matches!(&*socket.kind.lock(), net::sock::SockKind::Unix(_, _));
    let seqpacket = matches!(&*socket.kind.lock(),
        net::sock::SockKind::UnixMsgPair(pair, _) if pair.kind == net::UnixMsgKind::SeqPacket);
    let mut total = 0usize;
    loop {
        match crate::control::send_unix_once(ctx, socket, message, &scm, cap, total) {
            Ok(n) if stream && n != 0 => {
                total += n;
                if total >= message.payload.len() { return Ok(total); }
            }
            Ok(n) => return Ok(total.saturating_add(n)),
            Err(Error::Eagain) if nonblock => return if total == 0 { Err(Error::Eagain) } else { Ok(total) },
            Err(Error::Eagain) => {
                if sched::live::deliverable_signals_self() != 0 {
                    return if total == 0 { Err(Error::Eintr) } else { Ok(total) };
                }
                if deadline != 0 && monotonic_ns() >= deadline {
                    return if total == 0 { Err(Error::Eagain) } else { Ok(total) };
                }
                if let Err(error) = crate::control::wait_unix_send(socket, &scm,
                    message.payload.len().saturating_sub(total), cap, deadline)
                {
                    if total != 0 { return Ok(total); }
                    return if error == Error::Epipe && (stream || seqpacket) {
                        complete(ctx, flags, Err(error))
                    } else { Err(error) };
                }
            }
            Err(error) => {
                if total != 0 { return Ok(total); }
                return if error == Error::Epipe && (stream || seqpacket) {
                    complete(ctx, flags, Err(error))
                } else { Err(error) };
            }
        }
    }
}

/// Send one imported message through one retained and classified file. # C: backend-dependent
pub fn send(ctx: &SendContext<'_>, file: Arc<vfs::File>, message: Message, flags: u32)
    -> KResult<SendOutcome>
{
    let target = SendFile::new(file);
    send_retained(ctx, &target, message, flags, unresolved_address())
}

/// Retain the target, select Linux import ordering, and send one message. # C: backend-dependent
pub fn send_io<I: MessageIo>(ctx: &SendContext<'_>, flags: u32, io: &mut I)
    -> KResult<SendOutcome>
{
    let target = SendFile::new(io.file()?);
    if !target.is_socket() { return Err(Error::Enotsock); }
    let mode = match target.kind() {
        SendKind::Inet(socket) if flags as u64 & net::uapi::MSG_OOB != 0
            && matches!(*socket.kind.lock(), net::sock::SockKind::Raw4(_)
                | net::sock::SockKind::Raw6(_)) => ImportMode::RawOobEnvelope,
        SendKind::Vsock(_) if flags as u64 & net::uapi::MSG_OOB != 0 => ImportMode::RawOobEnvelope,
        _ => ImportMode::Full,
    };
    if mode == ImportMode::RawOobEnvelope {
        io.import(mode)?;
        return Err(Error::Eopnotsupp);
    }
    if let Some(mut message) = io.import_envelope()? {
        let prepared = prepare(ctx, &target, &message, flags)?;
        let tx_ring = matches!((&prepared, target.kind()),
            (PreparedSend::Inet(InetPrepared::Packet), SendKind::Inet(socket))
                if socket.has_packet_tx_ring());
        if !tx_ring { io.import_payload(&mut message)?; }
        return send_prepared(ctx, &target, message, flags, prepared);
    }
    send_retained(ctx, &target, io.import(mode)?, flags, unresolved_address())
}

/// Send one fully imported message through a retained target. # C: backend-dependent
pub(crate) fn send_retained(ctx: &SendContext<'_>, target: &SendFile, message: Message, flags: u32,
    _resolved: ResolvedAddress)
    -> KResult<SendOutcome>
{
    if !target.is_socket() { return Err(Error::Enotsock); }
    let envelope_only_oob = match target.kind() {
        SendKind::Vsock(_) => true,
        SendKind::Inet(socket) => matches!(*socket.kind.lock(),
            net::sock::SockKind::Raw4(_) | net::sock::SockKind::Raw6(_)),
        _ => false,
    };
    if flags as u64 & net::uapi::MSG_OOB != 0 && envelope_only_oob {
        return Err(Error::Eopnotsupp);
    }
    let prepared = prepare(ctx, target, &message, flags)?;
    send_prepared(ctx, target, message, flags, prepared)
}

/// Commit one prepared send using its retained family state. # C: backend-dependent
pub(crate) fn send_prepared(ctx: &SendContext<'_>, target: &SendFile, message: Message, flags: u32,
    prepared: PreparedSend) -> KResult<SendOutcome>
{
    let requested = message.requested_len;
    let bytes = match (target.kind(), prepared) {
        (SendKind::Netlink(socket), PreparedSend::Netlink { groups, pid }) => {
            if message.payload_faulted { return Err(Error::Efault); }
            send_netlink(socket, &message, groups, pid)
        }
        (SendKind::Vsock(_), PreparedSend::Vsock) => {
            if message.payload_faulted && message.payload.is_empty() { return Err(Error::Efault); }
            let result = if target.nonblock() || flags as u64 & net::uapi::MSG_DONTWAIT != 0 {
                target.file().inode().write_nonblock(0, &message.payload)
            } else { target.file().write(&message.payload) }.map_err(Error::from);
            complete(ctx, flags, result)
        }
        (SendKind::Inet(socket), PreparedSend::Inet(prepared)) => {
            if message.payload_faulted && (message.payload.is_empty()
                || matches!(*socket.kind.lock(), net::sock::SockKind::Udp
                    | net::sock::SockKind::UnixDgram(_) | net::sock::SockKind::UnixMsgPair(_, _)
                    | net::sock::SockKind::Packet { .. } | net::sock::SockKind::Raw4(_)
                    | net::sock::SockKind::Raw6(_)))
            { return Err(Error::Efault); }
            #[cfg(target_os = "oxide-kernel")]
            { send_inet(ctx, target, socket, &message, flags, prepared) }
            #[cfg(not(target_os = "oxide-kernel"))]
            {
                match prepared {
                    InetPrepared::Packet =>
                        crate::packet::send(socket, &message.payload, message.name.as_deref()),
                    _ => Err(Error::Eopnotsupp),
                }
            }
        }
        _ => return Err(Error::Enotsock),
    }?;
    Ok(SendOutcome { bytes, complete: bytes >= requested })
}
