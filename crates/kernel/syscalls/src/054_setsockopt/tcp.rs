#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use syscall::errno::Errno;

use super::optval::read_i32_required;
use super::uapi::*;

/// `setsockopt(fd, IPPROTO_TCP, ...)`. # C: O(1)
pub(super) fn set(sock: &Arc<net::sock::InetSocket>, optname: u64,
                  optval: u64, optlen: u32) -> i64 {
    match optname {
        TCP_NODELAY => {
            let v = match read_i32_required(optval, optlen) { Ok(v) => v, Err(e) => return e };
            sock.opts.tcp_nodelay.store(v, Ordering::Release);
        }
        TCP_CORK => {
            let v = match read_i32_required(optval, optlen) { Ok(v) => v, Err(e) => return e };
            let new = if v != 0 { 1 } else { 0 };
            let old = sock.opts.tcp_cork.swap(new, Ordering::AcqRel);
            if old != 0 && new == 0 { uncork(sock); }
        }
        TCP_KEEPIDLE => {
            let v = match read_i32_required(optval, optlen) { Ok(v) => v, Err(e) => return e };
            if v <= 0 { return -(Errno::Einval.as_i32() as i64); }
            sock.opts.tcp_keepidle_s.store(v, Ordering::Release);
            refresh_keepalive(sock);
        }
        TCP_KEEPINTVL => {
            let v = match read_i32_required(optval, optlen) { Ok(v) => v, Err(e) => return e };
            if v <= 0 { return -(Errno::Einval.as_i32() as i64); }
            sock.opts.tcp_keepintvl_s.store(v, Ordering::Release);
            refresh_keepalive(sock);
        }
        TCP_KEEPCNT => {
            let v = match read_i32_required(optval, optlen) { Ok(v) => v, Err(e) => return e };
            if v <= 0 { return -(Errno::Einval.as_i32() as i64); }
            sock.opts.tcp_keepcnt.store(v, Ordering::Release);
            refresh_keepalive(sock);
        }
        _ => return -(Errno::Enoprotoopt.as_i32() as i64),
    }
    0
}

/// Clearing `TCP_CORK` flushes whatever the cork held back. # C: O(1)
fn uncork(sock: &Arc<net::sock::InetSocket>) {
    let entry = match &*sock.kind.lock() {
        net::sock::SockKind::TcpConn(entry) => Some(entry.clone()),
        _ => None,
    };
    if let Some(entry) = entry {
        let nodelay = sock.opts.tcp_nodelay.load(Ordering::Acquire) != 0;
        let _ = net::sock::stack().tcp_send(&entry, &[], usize::MAX, nodelay, false);
        net::sock::drain_loopback();
    }
}

fn refresh_keepalive(sock: &Arc<net::sock::InetSocket>) {
    if let net::sock::SockKind::TcpConn(entry) = &*sock.kind.lock() {
        net::sock_opts::apply_tcp_keepalive_opts(sock, entry);
    }
}
