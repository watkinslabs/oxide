// SOL_SOCKET on an AF_NETLINK fd.
//
// SOL_SOCKET never reaches a family's own option table: it is answered once,
// generically, before family dispatch, and the family op sees only its own
// level. This module is that generic step for netlink until every family
// shares one socket base — it owns no decision of its own, deferring the
// credential gate, the flag and its value to `net::scm`, and the receive
// timeout to the socket's canonical field.

use syscall::errno::Errno;

use super::NetlinkFileRef;

const SO_RCVTIMEO_OLD: u64 = 20;
const TIMEVAL_BYTES: u64 = 16;
const INT_BYTES: u64 = core::mem::size_of::<i32>() as u64;
const NSEC_PER_SEC: i128 = 1_000_000_000;
const NSEC_PER_USEC: i128 = 1_000;

fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }

fn read_int(optval: u64) -> Result<i32, i64> {
    let mut raw = [0u8; core::mem::size_of::<i32>()];
    uaccess::copy_from_user(&mut raw, optval).map_err(|_| errno(Errno::Efault))?;
    Ok(i32::from_ne_bytes(raw))
}

/// `sock_setsockopt` for a netlink socket. # C: O(1)
pub fn set(target: &NetlinkFileRef, optname: u64, optval: u64, optlen: u64) -> i64 {
    let socket = target.socket();
    match optname {
        net::sock_opts::sol_socket::SO_PASSCRED => {
            if !net::scm::may_scm_recv(net::socket_args::AF_NETLINK as u16) {
                return errno(Errno::Eopnotsupp);
            }
            if optlen < INT_BYTES { return errno(Errno::Einval); }
            match read_int(optval) {
                Ok(v) => { socket.scm.set(v != 0); 0 }
                Err(e) => e,
            }
        }
        // `sk_rcvtimeo`, read back by the receive wait for `sock_intr_errno`:
        // without it a timed netlink receive is impossible and every
        // interrupted one must report ERESTARTSYS.
        SO_RCVTIMEO_OLD => {
            if optlen < TIMEVAL_BYTES { return errno(Errno::Einval); }
            let mut raw = [0u8; TIMEVAL_BYTES as usize];
            if uaccess::copy_from_user(&mut raw, optval).is_err() { return errno(Errno::Efault); }
            let sec = i64::from_ne_bytes(raw[..8].try_into().unwrap());
            let usec = i64::from_ne_bytes(raw[8..].try_into().unwrap());
            let ns = (sec.max(0) as i128 * NSEC_PER_SEC + usec.max(0) as i128 * NSEC_PER_USEC)
                .min(u64::MAX as i128) as u64;
            socket.rcvtimeo_ns.store(ns, core::sync::atomic::Ordering::Release);
            0
        }
        _ => 0,
    }
}

/// `sock_getsockopt` for a netlink socket. `None` when the option is not one
/// this level answers, so the caller falls through to its own table. # C: O(1)
pub fn get(target: &NetlinkFileRef, optname: u64) -> Option<Result<alloc::vec::Vec<u8>, i64>> {
    let socket = target.socket();
    match optname {
        net::sock_opts::sol_socket::SO_PASSCRED => {
            if !net::scm::may_scm_recv(net::socket_args::AF_NETLINK as u16) {
                return Some(Err(errno(Errno::Eopnotsupp)));
            }
            Some(Ok(socket.scm.value().to_ne_bytes().to_vec()))
        }
        _ => None,
    }
}
