use alloc::sync::Arc;
use syscall::errno::Errno;

use crate::net_common::errno_from_neterr;
use super::packet_abi::{parse_packet_mreq, PACKET_MREQ_MAX_SIZE, PACKET_MREQ_SIZE};

pub(super) fn packet_membership(sock: &Arc<net::sock::InetSocket>, optval: u64,
                                optlen: u32, add: bool) -> i64 {
    if !matches!(*sock.kind.lock(), net::sock::SockKind::Packet { .. }) {
        return -(Errno::Enoprotoopt.as_i32() as i64);
    }
    if optlen < PACKET_MREQ_SIZE as u32 { return -(Errno::Einval.as_i32() as i64); }
    let copy_len = core::cmp::min(optlen as usize, PACKET_MREQ_MAX_SIZE);
    let mut bytes = alloc::vec![0u8; copy_len];
    if uaccess::copy_from_user(&mut bytes, optval).is_err() {
        return -(Errno::Efault.as_i32() as i64);
    }
    let request = match parse_packet_mreq(&bytes, optlen as usize) {
        Some(request) => request,
        None => return -(Errno::Einval.as_i32() as i64),
    };
    match sock.change_packet_membership(request, add) {
        Ok(()) => 0,
        Err(error) => errno_from_neterr(error),
    }
}
