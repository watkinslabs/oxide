// Socket option helpers split out of sock.rs to keep the socket wrapper under
// the per-file size cap.

use crate::sock::InetSocket;
use crate::stack::TcpEntry;

pub const TCP_KEEPIDLE_DEFAULT_S: i32 = 7200;
pub const TCP_KEEPINTVL_DEFAULT_S: i32 = 75;
pub const TCP_KEEPCNT_DEFAULT: i32 = 9;

/// Apply the canonical namespace security decision for socket option access.
/// ABI code calls this boundary but does not implement policy itself. # C: O(1)
pub fn check_option(sock: &InetSocket) -> Result<(), crate::NetError> {
    let context = security::network::Context {
        namespace: sock.net_ns(),
        family: sock.family.load(core::sync::atomic::Ordering::Acquire),
        socket_type: 0, protocol: 0,
        operation: security::network::Operation::Option,
    };
    if matches!(security::network::evaluate(context), security::network::Verdict::Deny) {
        return Err(crate::NetError::Eacces);
    }
    Ok(())
}

/// Canonical security admission for socketpair creation. # C: O(1)
pub fn check_socketpair(namespace: u64, family: u16, socket_type: u32, protocol: u32)
    -> Result<(), crate::NetError>
{
    let context = security::network::Context { namespace, family, socket_type, protocol,
        operation: security::network::Operation::SocketPair };
    if matches!(security::network::evaluate(context), security::network::Verdict::Deny) {
        return Err(crate::NetError::Eacces);
    }
    Ok(())
}

/// Canonical security admission for local/peer name snapshots. # C: O(1)
pub fn check_name_query(namespace: u64, family: u16) -> Result<(), crate::NetError> {
    crate::security_admission::check(namespace, family, security::network::Operation::NameQuery)
}

/// Canonical security admission for integer ioctl access. # C: O(1)
pub fn check_ioctl(namespace: u64, family: u16) -> Result<(), crate::NetError> {
    crate::security_admission::check(namespace, family, security::network::Operation::Ioctl)
}

/// Sender credentials for AF_UNIX SCM_CREDENTIALS. Caller fetches from
/// `sched::current()` and passes the snapshot through the socket layer.
#[derive(Copy, Clone, Debug, Default)]
pub struct SenderCreds {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

fn keepalive_secs_to_ns(secs: i32) -> u64 {
    (secs.max(1) as u64).saturating_mul(1_000_000_000)
}

/// Copy listener TCP keepalive policy to an accepted socket. # C: O(1)
pub fn inherit_tcp_keepalive_opts(dst: &InetSocket, src: &InetSocket) {
    use core::sync::atomic::Ordering;
    dst.opts.keepalive.store(src.opts.keepalive.load(Ordering::Acquire), Ordering::Release);
    dst.opts.tcp_keepidle_s.store(src.opts.tcp_keepidle_s.load(Ordering::Acquire), Ordering::Release);
    dst.opts.tcp_keepintvl_s.store(src.opts.tcp_keepintvl_s.load(Ordering::Acquire), Ordering::Release);
    dst.opts.tcp_keepcnt.store(src.opts.tcp_keepcnt.load(Ordering::Acquire), Ordering::Release);
}

/// Apply socket-level keepalive configuration to a live TCP TCB. # C: O(1)
pub fn apply_tcp_keepalive_opts(sock: &InetSocket, entry: &TcpEntry) {
    use core::sync::atomic::Ordering;
    let mut c = entry.conn.lock();
    c.ka_enabled = sock.opts.keepalive.load(Ordering::Acquire) != 0;
    c.ka_idle_ns = keepalive_secs_to_ns(sock.opts.tcp_keepidle_s.load(Ordering::Acquire));
    c.ka_intvl_ns = keepalive_secs_to_ns(sock.opts.tcp_keepintvl_s.load(Ordering::Acquire));
    c.ka_cnt_max = sock.opts.tcp_keepcnt.load(Ordering::Acquire).max(1) as u32;
    c.ka_count = 0;
    c.next_ka_ns = 0;
}
