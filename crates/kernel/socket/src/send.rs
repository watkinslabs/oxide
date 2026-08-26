use alloc::{boxed::Box, sync::Arc};
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
    sandbox: Option<Arc<landlock::Domain>>,
}

/// Linux's `struct used_address`, kept on the batch stack without an
/// allocation. It intentionally caches only an explicit destination and only
/// the last successful message's destination. # C: O(address length)
#[derive(Clone, Copy)]
pub(crate) struct UsedAddress {
    bytes: [u8; 128],
    len: usize,
    valid: bool,
}

impl UsedAddress {
    pub(crate) const fn empty() -> Self {
        Self { bytes: [0; 128], len: 0, valid: false }
    }

    pub(crate) fn from_name(name: Option<&[u8]>) -> Self {
        let Some(name) = name else { return Self::empty() };
        if name.len() > 128 { return Self::empty() }
        let mut address = Self { bytes: [0; 128], len: name.len(), valid: true };
        address.bytes[..name.len()].copy_from_slice(name);
        address
    }

    pub(crate) fn matches(&self, name: Option<&[u8]>) -> bool {
        let Some(name) = name else { return false };
        self.valid && self.len == name.len() && self.bytes[..self.len] == *name
    }
}

impl<'a> SendContext<'a> {
    /// Capture explicit task state needed by socket send policy. The sandbox
    /// domain is snapshotted once so every message of a batch is judged against
    /// the policy the call started under. # C: O(1)
    pub fn new(task: &'a sched::Task) -> Self {
        Self { task, sandbox: task.security.landlock_domain.lock().clone() }
    }

    /// Build a sender context with an explicit sandbox snapshot. # C: O(1)
    pub fn with_sandbox(task: &'a sched::Task, sandbox: Option<Arc<landlock::Domain>>) -> Self {
        Self { task, sandbox }
    }

    /// Snapshot sender credentials from the retained task context. An
    /// unsolicited AF_UNIX credential reports the sender's REAL uid/gid — the
    /// effective pair belongs to `SO_PEERCRED`, not to `SCM_CREDENTIALS`.
    /// # C: O(1)
    pub(crate) fn creds(&self) -> net::sock::SenderCreds {
        net::sock::SenderCreds {
            pid: self.task.visible_pid(),
            uid: self.task.security.creds.ruid.load(Ordering::Acquire),
            gid: self.task.security.creds.rgid.load(Ordering::Acquire),
        }
    }

    /// Borrow the retained sender task context. # C: O(1)
    pub(crate) fn task(&self) -> &sched::Task { self.task }

    /// Sandbox policy retained for this send. # C: O(1)
    pub(crate) fn sandbox(&self) -> Option<&Arc<landlock::Domain>> { self.sandbox.as_ref() }
}

/// Apply shared stream SIGPIPE completion semantics. # C: O(1)
pub(crate) fn complete(_ctx: &SendContext<'_>, flags: u32, result: KResult<usize>) -> KResult<usize> {
    if result == Err(Error::Epipe) && flags & net::uapi::MSG_NOSIGNAL as u32 == 0 {
        // Linux `sk_stream_wait_connect`/`tcp_sendmsg` -> `send_sig(SIGPIPE,
        // current, 0)`: the write-side EPIPE report is a signal on the CALLING
        // thread, queued with `si_code = SI_KERNEL`. The bit-only post this
        // replaced was invisible to `signalfd` and carried no record.
        sched::live::send_signal_self(Signum::Sigpipe);
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

/// Resolve one netlink send destination: the supplied `msg_name`, else the
/// socket's connected destination. Only the supplied one is capability-gated;
/// the connected pair was admitted when the socket connected. # C: O(1)
fn netlink_address(socket: &netlink::NetlinkSocket, message: &Message)
    -> KResult<netlink::NlDest>
{
    match message.name.as_deref() {
        None => Ok(socket.destination()),
        Some(name) => netlink::parse_supplied_dest(name, socket.protocol, socket.net_admin())
            .map_err(Error::from),
    }
}

fn send_netlink(socket: &netlink::NetlinkSocket, message: &Message, dest: netlink::NlDest,
    nonblock: bool) -> KResult<usize>
{
    socket.send_to(&message.payload, dest, nonblock).map_err(Error::from)
}

pub(crate) enum InetPrepared {
    Packet,
    Unix(Box<crate::control::UnixScm>),
    /// The settled transmit overrides live on the heap, not in this enum: the
    /// value would otherwise be copied into three stack frames that all sit
    /// under the deepest send path in the tree, once each.
    Transport(crate::address::InetAddress, alloc::boxed::Box<net::send_control::SendControl>,
        Option<net::landlock_addr::UdpAutobindAdmission>),
}

pub(crate) enum PreparedSend {
    Netlink(netlink::NlDest),
    Vsock,
    Inet(InetPrepared),
}

#[cfg(target_os = "oxide-kernel")]
#[path = "send/transport.rs"]
mod transport;
#[cfg(target_os = "oxide-kernel")]
use transport::send_inet;

/// Validate family policy and retain backend state before payload import.
///
/// `#[inline(never)]`: every family's validation working set — the decoded
/// address, the ancillary overrides, the pinned SCM state — is live only
/// until the send is prepared, so its frame must overlap the transmit path
/// below rather than sum with it (Linux `noinline_for_stack`).
/// # C: backend-dependent
#[inline(never)]
pub(crate) fn prepare(ctx: &SendContext<'_>, target: &SendFile, message: &Message, flags: u32)
    -> KResult<PreparedSend>
{
    prepare_inner(ctx, target, message, flags, false)
}

/// Prepare a batched message, retaining Linux's repeated-destination security
/// decision cache while still running all family validation and control work.
#[inline(never)]
pub(crate) fn prepare_cached(ctx: &SendContext<'_>, target: &SendFile, message: &Message,
    flags: u32, used_address: &UsedAddress) -> KResult<PreparedSend>
{
    prepare_inner(ctx, target, message, flags, used_address.matches(message.name.as_deref()))
}

#[inline(never)]
fn prepare_inner(ctx: &SendContext<'_>, target: &SendFile, message: &Message, flags: u32,
    skip_socket_hook: bool) -> KResult<PreparedSend>
{
    let admission = crate::security::admit_cached(ctx, target, message, flags,
        skip_socket_hook)?;
    match target.kind() {
        SendKind::File => Err(Error::Enotsock),
        SendKind::Netlink(socket) => {
            if flags as u64 & net::uapi::MSG_OOB != 0 { return Err(Error::Eopnotsupp); }
            if message.requested_len == 0 { return Err(Error::Enodata); }
            crate::control::validate_scm_no_rights(ctx, &message.control)?;
            let dest = netlink_address(socket, message)?;
            socket.preflight_send(message.requested_len).map_err(Error::from)?;
            Ok(PreparedSend::Netlink(dest))
        }
        SendKind::Vsock(socket) => {
            // A vsock socket consults no ancillary data on send: it has no
            // control message of its own and never runs the generic rule, so
            // whatever the caller attached is stepped over rather than judged.
            crate::vsock_addr::admit_destination(socket, message.name.as_deref())?;
            Ok(PreparedSend::Vsock)
        }
        SendKind::Inet(socket) => {
            if let Some(result) = crate::control::prepare_unix(ctx, socket, message, flags) {
                return result.map(|scm| PreparedSend::Inet(InetPrepared::Unix(Box::new(scm))));
            }
            if matches!(*socket.kind.lock(), net::sock::SockKind::Packet { .. }) {
                crate::packet::validate(message.name.as_deref())?;
                crate::control_family::admit(ctx, socket, &message.control, None)?;
                return Ok(PreparedSend::Inet(InetPrepared::Packet));
            }
            // "Mirror BSD error message compatibility": the IPv4 datagram
            // sender has no out-of-band channel and says so before it looks at
            // the destination. The IPv6 sender carries no such check, so an
            // AF_INET6 socket only reaches it once its destination has been
            // decoded and found to be v4-mapped.
            let oob = flags as u64 & net::uapi::MSG_OOB != 0;
            let udp = matches!(*socket.kind.lock(), net::sock::SockKind::Udp);
            if udp && oob
                && socket.family.load(Ordering::Acquire) != net::socket_args::AF_INET6 as u16
            { return Err(Error::Eopnotsupp); }
            let address = crate::address::inet_for_socket(message.name.as_deref(),
                socket.family.load(Ordering::Acquire))?;
            if udp && oob && crate::control_family::ipv4_send_path(socket, Some(&address)) {
                return Err(Error::Eopnotsupp);
            }
            let mut control = crate::control_family::admit(ctx, socket, &message.control,
                Some(&address))?;
            crate::control_family::settle(socket, &address, &mut control, flags as u64);
            Ok(PreparedSend::Inet(InetPrepared::Transport(address,
                alloc::boxed::Box::new(control), admission.udp_autobind)))
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
            && raw_envelope_socket(socket) => ImportMode::RawOobEnvelope,
        SendKind::Vsock(_) if flags as u64 & net::uapi::MSG_OOB != 0 => ImportMode::RawOobEnvelope,
        _ => ImportMode::Full,
    };
    if mode == ImportMode::RawOobEnvelope {
        // The envelope is imported before the hook, exactly as an ordinary
        // send imports its header first: a caller whose address or ancillary
        // memory is unreadable owes EFAULT, not a permission answer. The
        // absent out-of-band channel is the protocol's answer and comes last.
        let message = io.import(mode)?;
        crate::security::admit(ctx, &target, &message, flags)?;
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

/// Whether a socket discards an out-of-band send without importing its payload.
/// A raw socket does; an ICMP datagram endpoint does not, because it screens the
/// message length before it reports the absent out-of-band channel. # C: O(1)
fn raw_envelope_socket(socket: &Arc<net::sock::InetSocket>) -> bool {
    match &*socket.kind.lock() {
        net::sock::SockKind::Raw4(endpoint) => !endpoint.is_ping(),
        net::sock::SockKind::Raw6(endpoint) => !endpoint.is_ping(),
        _ => false,
    }
}

/// Send one fully imported message through a retained target. # C: backend-dependent
pub(crate) fn send_retained(ctx: &SendContext<'_>, target: &SendFile, message: Message, flags: u32,
    _resolved: ResolvedAddress)
    -> KResult<SendOutcome>
{
    if !target.is_socket() { return Err(Error::Enotsock); }
    let envelope_only_oob = match target.kind() {
        SendKind::Vsock(_) => true,
        SendKind::Inet(socket) => raw_envelope_socket(socket),
        _ => false,
    };
    if flags as u64 & net::uapi::MSG_OOB != 0 && envelope_only_oob {
        crate::security::admit(ctx, target, &message, flags)?;
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
        (SendKind::Netlink(socket), PreparedSend::Netlink(dest)) => {
            if message.payload_faulted { return Err(Error::Efault); }
            let nonblock = target.nonblock() || flags as u64 & net::uapi::MSG_DONTWAIT != 0;
            send_netlink(socket, &message, dest, nonblock)
        }
        (SendKind::Vsock(socket), PreparedSend::Vsock) => {
            if message.payload_faulted && message.payload.is_empty() { return Err(Error::Efault); }
            let nonblock = target.nonblock() || flags as u64 & net::uapi::MSG_DONTWAIT != 0;
            let end_of_record = flags as u64 & net::uapi::MSG_EOR != 0;
            let result = socket.send_message_flags(&message.payload, end_of_record, nonblock,
                flags as u64)
                .map_err(Error::from);
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
            { send_inet(ctx, target, socket, &message, flags, Box::new(prepared)) }
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
    // The completion a `MSG_ZEROCOPY` send owes the error queue is published
    // once, here, for every family that offers the option.
    if let SendKind::Inet(socket) = target.kind() {
        socket.complete_zerocopy_send(flags as u64 & net::uapi::MSG_ZEROCOPY != 0, bytes);
    }
    Ok(SendOutcome { bytes, complete: bytes >= requested })
}
