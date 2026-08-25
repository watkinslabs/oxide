// `IPPROTO_TCP` argument import + application for slot 54. The option table,
// value windows, capability ladder, and errno ordering live in
// `net::sock_opts::sol_tcp` (`docs/53§4`); this file only moves bytes, reads
// the live connection state the table judges against, and installs results.
#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use syscall::errno::Errno;

use net::sock::{InetSocket, SockKind};
use net::sock_opts::sol_tcp::{self as sol, CA_NAME_MAX, ULP_NAME_MAX};
use net::sock_opts::sol_tcp::set::{self, Action, Arg, ArgClass, SetEnv};
use net::tcp_state::TcpState;

fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// `setsockopt(fd, IPPROTO_TCP, ...)`. # C: O(optlen)
pub(super) fn set(sock: &Arc<InetSocket>, optname: u64, optval: u64, optlen: u32) -> i64 {
    let arg = match import(optname, optval, optlen) { Ok(a) => a, Err(e) => return errno(e) };
    let env = env_for(sock);
    let action = match set::admit(optname, arg, env) { Ok(a) => a, Err(e) => return errno(e) };
    apply(sock, &action)
}

/// Import the caller's argument. The name and key options are screened on
/// their own shapes; every other option number — including one the table does
/// not know — passes the leading `int` screen first, so a short buffer is
/// `EINVAL` and a faulting one `EFAULT` ahead of `ENOPROTOOPT`. # C: O(optlen)
fn import(optname: u64, optval: u64, optlen: u32) -> Result<Arg, Errno> {
    match set::arg_class(optname) {
        ArgClass::Name => {
            if optlen < 1 { return Err(Errno::Einval); }
            let cap = if optname == sol::TCP_ULP { ULP_NAME_MAX } else { CA_NAME_MAX };
            Ok(Arg::Name(read_name(optval, optlen, cap)?))
        }
        ArgClass::FastopenKey => {
            let len = optlen as usize;
            if len != net::tcp_fastopen::KEY_LEN && len != net::tcp_fastopen::KEY_BUF_LEN {
                return Err(Errno::Einval);
            }
            let raw = read_vec(optval, len)?;
            let mut primary = [0u8; net::tcp_fastopen::KEY_LEN];
            primary.copy_from_slice(&raw[..net::tcp_fastopen::KEY_LEN]);
            let backup = (len == net::tcp_fastopen::KEY_BUF_LEN).then(|| {
                let mut b = [0u8; net::tcp_fastopen::KEY_LEN];
                b.copy_from_slice(&raw[net::tcp_fastopen::KEY_LEN..]);
                b
            });
            Ok(Arg::FastopenKey { primary, backup })
        }
        ArgClass::RepairWindow => {
            super::optval::read_i32_required(optval, optlen).map_err(decode)?;
            // The repair ladder and the length screen both run before the
            // copy, so the copy is only attempted at the length that can pass.
            let value = if optlen as usize == sol::REPAIR_WINDOW_LEN {
                read_vec(optval, sol::REPAIR_WINDOW_LEN).map(|raw| {
                    let mut fixed = [0u8; sol::REPAIR_WINDOW_LEN];
                    fixed.copy_from_slice(&raw);
                    sol::RepairWindow::from_bytes(&fixed)
                })
            } else { Ok(sol::RepairWindow::default()) };
            Ok(Arg::RepairWindow { optlen, value })
        }
        ArgClass::RepairOptions => {
            super::optval::read_i32_required(optval, optlen).map_err(decode)?;
            let whole = optlen as usize - (optlen as usize % sol::REPAIR_OPT_LEN);
            Ok(Arg::RepairOptions(read_vec(optval, whole).map(|raw| sol::RepairOpt::parse(&raw))))
        }
        ArgClass::Int => Ok(Arg::Int(
            super::optval::read_i32_required(optval, optlen).map_err(decode)?)),
    }
}

/// Recover the `Errno` the shared `int` importer already encoded. # C: O(1)
fn decode(raw: i64) -> Errno {
    if raw == -(Errno::Einval.as_i32() as i64) { Errno::Einval } else { Errno::Efault }
}

fn read_vec(optval: u64, len: usize) -> Result<Vec<u8>, Errno> {
    let mut raw = alloc::vec![0u8; len];
    if len != 0 && uaccess::copy_from_user(&mut raw, optval).is_err() { return Err(Errno::Efault); }
    Ok(raw)
}

/// A NUL-terminated name truncated to the option's own buffer. # C: O(cap)
fn read_name(optval: u64, optlen: u32, cap: usize) -> Result<Vec<u8>, Errno> {
    let take = core::cmp::min(cap - 1, optlen as usize);
    let raw = read_vec(optval, take)?;
    let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
    Ok(raw[..end].to_vec())
}

/// The live connection state the option table judges a write against.
/// # C: O(retransmit queue)
fn env_for(sock: &Arc<InetSocket>) -> SetEnv {
    let tcp = &sock.opts.tcp;
    let now_ms = net::tcp_conn::tcp_now_ms() as i32;
    let mut env = SetEnv {
        net_admin: net_admin(sock),
        state: TcpState::Closed,
        repair: tcp.repair.load(Ordering::Acquire),
        repair_queue: tcp.repair_queue.load(Ordering::Acquire),
        rtx_queue_empty: true,
        recv_queue_drained: true,
        ack_scheduled: false,
        bytes_sent: false,
        cc_locked: false,
        current_algo: tcp.algo(),
        fastopen_sysctl: net::sock::tcp_fastopen::setsockopt_bits(sock),
        somaxconn: net::sysctl::somaxconn() as i32,
        rcv_nxt: 0,
        clock_ts_ms: now_ms,
        clock_ts_us: now_ms.wrapping_mul(1000),
    };
    match &*sock.kind.lock() {
        SockKind::TcpListener(_) => env.state = TcpState::Listen,
        SockKind::TcpConn(entry) => {
            let c = entry.conn.lock();
            env.state = c.state;
            env.rtx_queue_empty = c.retx_q.is_empty();
            env.recv_queue_drained = c.rcv_nxt == c.rcv_read_seq;
            env.ack_scheduled = c.ack_pending;
            env.bytes_sent = c.snd_nxt != c.snd_una || !c.retx_q.is_empty();
            env.cc_locked = c.cc_locked;
            env.rcv_nxt = c.rcv_nxt;
        }
        _ => {}
    }
    env
}

fn net_admin(sock: &InetSocket) -> bool {
    match sched::live::current() {
        Some(cur) => nscg::has_net_admin_for(cur, &sock.net_namespace),
        None => false,
    }
}

/// Store the accepted write and run the transport actions it implies.
/// # C: O(send buffer) when the write releases held data
fn apply(sock: &Arc<InetSocket>, action: &Action) -> i64 {
    use net::sock_opts::sol_tcp::apply as install;
    let effects = install::store(&sock.opts, action);
    net::sock::tcp_fastopen::complete_setsockopt(sock, &effects);
    let entry = match &*sock.kind.lock() {
        SockKind::TcpConn(entry) => Some(entry.clone()),
        SockKind::TcpListener(listener) => {
            if effects.listener { install::to_listener(&sock.opts, listener); }
            None
        }
        _ => None,
    };
    if let Some(entry) = &entry {
        {
            let mut c = entry.conn.lock();
            install::repair_to_conn(&mut c, action);
            if effects.reload { install::to_conn(&sock.opts, &mut c); }
        }
        if effects.reload { net::sock_opts::apply_tcp_keepalive_opts(sock, entry); }
        if effects.push_ack || effects.window_probe { install::push_pending_ack(entry); }
        if effects.uncork { uncork(sock, entry); }
        if effects.write_space { install::notify_write_space(entry); }
    }
    if let Action::RepairOptions { err: Some(e), .. } = action { return errno(*e); }
    0
}

/// Clearing the cork flushes whatever it held back. # C: O(send buffer)
fn uncork(sock: &Arc<InetSocket>, entry: &Arc<net::stack::TcpEntry>) {
    let nodelay = sock.opts.tcp_nodelay.load(Ordering::Acquire) != 0;
    let _ = net::sock::stack().tcp_send(entry, &[], usize::MAX, nodelay, false);
    net::sock::drain_loopback();
}
