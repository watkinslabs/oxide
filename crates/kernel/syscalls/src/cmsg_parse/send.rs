use alloc::sync::Arc;
use alloc::vec::Vec;

use net::sock::{InetSocket, SenderCreds, SockKind};
use syscall::errno::Errno;
use vfs::File;

use super::parse::parse_scm;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Handle AF_UNIX ancillary data from kernel-owned snapshots. `None` means the
/// socket/control combination needs ordinary sendmsg dispatch. # C: O(control + payload)
pub fn try_sendmsg_with_control(sock: &Arc<InetSocket>, name: &[u8], payload: &[u8],
    control: &[u8], flags: u64) -> Option<i64>
{
    if control.is_empty() { return None; }
    let kind = match &*sock.kind.lock() {
        SockKind::UnixDgram(_) => 1,
        SockKind::Unix(_, _) => 2,
        SockKind::UnixMsgPair(_, _) => 3,
        _ => return None,
    };
    let scm = match parse_scm(control, true) { Ok(scm) => scm, Err(e) => return Some(e) };
    match kind {
        1 => Some(sendmsg_unix_dgram_with_fds(sock, name, payload, scm.fds, scm.creds)),
        2 | 3 => Some(sendmsg_unix_stream_with_fds(sock, payload, scm.fds, scm.creds, flags)),
        _ => None,
    }
}

/// Validate generic send-side SOL_SOCKET controls for a non-UNIX socket. # C: O(control)
pub fn validate_non_unix_control(control: &[u8]) -> Result<(), i64> {
    if control.is_empty() { return Ok(()); }
    parse_scm(control, false).map(|_| ())
}

pub fn sendmsg_unix_stream_with_fds(sock: &Arc<InetSocket>, payload: &[u8],
    fds: Vec<Arc<File>>, creds: Option<SenderCreds>, flags: u64) -> i64
{
    enum Target { Stream(Arc<net::UnixPair>, net::UnixEnd), Msg(Arc<net::UnixMsgPair>, net::UnixEnd) }
    let target = match &*sock.kind.lock() {
        SockKind::Unix(pair, end) => Target::Stream(pair.clone(), *end),
        SockKind::UnixMsgPair(pair, end) => Target::Msg(pair.clone(), *end),
        _ => return err(Errno::Einval),
    };
    let rights = net::classify_files(fds);
    let signal = matches!(target, Target::Stream(_, _));
    let result = match target {
        Target::Stream(pair, end) => match (match creds {
            Some(c) => pair.write_with_rights_and_creds(end, payload, rights, (c.pid, c.uid, c.gid)),
            None => pair.write_with_rights(end, payload, rights),
        }) {
            Ok(n) => n as i64, Err(net::UnixStreamError::PeerClosed) => err(Errno::Epipe),
        },
        Target::Msg(pair, end) => match (match creds {
            Some(c) => pair.send_with_rights_and_creds(end, payload, rights, (c.pid, c.uid, c.gid)),
            None => pair.send_with_rights(end, payload, rights),
        }) {
            Ok(n) => n as i64,
            Err(net::UnixMsgError::PeerClosed) => err(Errno::Epipe),
            Err(net::UnixMsgError::PeerRefused) => err(Errno::Econnrefused),
        },
    };
    if signal { crate::s044_sendto::finish_stream_send(flags, result) } else { result }
}

pub fn sendmsg_unix_dgram_with_fds(sock: &Arc<InetSocket>, name: &[u8], payload: &[u8],
    fds: Vec<Arc<File>>, supplied_creds: Option<SenderCreds>) -> i64
{
    if sock.write_shut.load(core::sync::atomic::Ordering::Acquire) { return err(Errno::Epipe); }
    let sender = match &*sock.kind.lock() {
        SockKind::UnixDgram(q) => q.bound(), _ => return err(Errno::Einval),
    };
    let addr = if !name.is_empty() {
        if name.len() < 2 { return err(Errno::Einval); }
        if u16::from_ne_bytes(name[..2].try_into().unwrap()) != 1 { return err(Errno::Eafnosupport); }
        let path = match crate::net_sockaddr::unix_path_from_kernel_sockaddr(name) { Ok(p) => p, Err(e) => return e };
        match crate::namei_common::resolve_unix_addr(path) { Ok(a) => a, Err(e) => return e }
    } else {
        match &*sock.kind.lock() {
            SockKind::UnixDgram(q) => match q.peer() { Some(p) => p, None => return err(Errno::Edestaddrreq) },
            _ => return err(Errno::Einval),
        }
    };
    let q = match net::net_ns::unix_registry_for_addr(&addr).dgram_lookup_addr(&addr) {
        Some(q) => q, None => return err(Errno::Econnrefused),
    };
    let creds = supplied_creds.unwrap_or_else(|| match sched::live::current() {
        Some(t) => SenderCreds { pid: t.visible_pid(),
            uid: t.creds.euid.load(core::sync::atomic::Ordering::Acquire),
            gid: t.creds.egid.load(core::sync::atomic::Ordering::Acquire) },
        None => SenderCreds::default(),
    });
    net::trace_dgram_journal(&addr.display, payload);
    let dgram = net::UnixDgram { payload: payload.to_vec(), creds: (creds.pid, creds.uid, creds.gid), fds: Vec::new() };
    match q.try_push_from_with_rights(dgram, sender, net::classify_files(fds)) {
        Ok(()) => payload.len() as i64, Err(e) => crate::net_common::errno_from_neterr(e),
    }
}
