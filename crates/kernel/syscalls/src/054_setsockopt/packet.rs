use alloc::sync::Arc;
use syscall::errno::Errno;

use crate::net_common::errno_from_neterr;
use super::packet_abi::{parse_packet_bool, parse_packet_flag, parse_packet_mreq,
                        parse_packet_version, parse_packet_fanout, PACKET_FANOUT_ARGS_SIZE,
                        PACKET_MREQ_MAX_SIZE, PACKET_MREQ_SIZE};

/// Import and dispatch one Linux AF_PACKET option. # C: O(optlen + memberships)
pub(super) fn packet_setsockopt(sock: &Arc<net::sock::InetSocket>, optname: u64,
                               optval: u64, optlen: u32) -> i64 {
    if !matches!(*sock.kind.lock(), net::sock::SockKind::Packet { .. }) {
        return -(Errno::Enoprotoopt.as_i32() as i64);
    }
    match optname {
        net::uapi::PACKET_ADD_MEMBERSHIP => packet_membership(sock, optval, optlen, true),
        net::uapi::PACKET_DROP_MEMBERSHIP => packet_membership(sock, optval, optlen, false),
        net::uapi::PACKET_AUXDATA => packet_flag(sock, optval, optlen,
            net::sock::InetSocket::set_packet_auxdata),
        net::uapi::PACKET_ORIGDEV => packet_flag(sock, optval, optlen,
            net::sock::InetSocket::set_packet_origdev),
        net::uapi::PACKET_VERSION => packet_version(sock, optval, optlen),
        net::uapi::PACKET_FANOUT => packet_fanout(sock, optval, optlen),
        net::uapi::PACKET_FANOUT_DATA => packet_fanout_data(sock, optval, optlen),
        net::uapi::PACKET_IGNORE_OUTGOING => packet_ignore_outgoing(sock, optval, optlen),
        _ => -(Errno::Enoprotoopt.as_i32() as i64),
    }
}

fn packet_fanout(sock: &Arc<net::sock::InetSocket>, optval: u64, optlen: u32) -> i64 {
    if !matches!(optlen as usize, 4 | PACKET_FANOUT_ARGS_SIZE) {
        return -(Errno::Einval.as_i32() as i64);
    }
    let mut bytes = [0u8; PACKET_FANOUT_ARGS_SIZE];
    if uaccess::copy_from_user(&mut bytes[..optlen as usize], optval).is_err() {
        return -(Errno::Efault.as_i32() as i64);
    }
    let Some(request) = parse_packet_fanout(&bytes[..optlen as usize]) else {
        return -(Errno::Einval.as_i32() as i64);
    };
    match sock.join_packet_fanout(request) {
        Ok(()) => 0,
        Err(error) => errno_from_neterr(error),
    }
}

fn packet_fanout_data(sock: &Arc<net::sock::InetSocket>, optval: u64, optlen: u32) -> i64 {
    if sock.bpf_filter.is_locked() { return -(Errno::Eperm.as_i32() as i64); }
    let program = match sock.packet_fanout_mode() {
        Ok(net::uapi::PACKET_FANOUT_CBPF) => {
            let header = match super::main::classic_filter_header(optval, optlen) {
                Ok(header) => header, Err(error) => return -(error.as_i32() as i64),
            };
            match super::main::classic_filter_program(header) {
                Ok(program) => program, Err(error) => return -(error.as_i32() as i64),
            }
        }
        Ok(net::uapi::PACKET_FANOUT_EBPF) => {
            if optlen != core::mem::size_of::<i32>() as u32 {
                return -(Errno::Einval.as_i32() as i64);
            }
            let mut bytes = [0u8; core::mem::size_of::<i32>()];
            if uaccess::copy_from_user(&mut bytes, optval).is_err() {
                return -(Errno::Efault.as_i32() as i64);
            }
            match super::main::bpf_prog(i32::from_ne_bytes(bytes)) {
                Ok(program) => program, Err(error) => return -(error.as_i32() as i64),
            }
        }
        Ok(_) | Err(_) => return -(Errno::Einval.as_i32() as i64),
    };
    match sock.set_packet_fanout_data(program) {
        Ok(()) => 0,
        Err(error) => errno_from_neterr(error),
    }
}

fn packet_version(sock: &Arc<net::sock::InetSocket>, optval: u64, optlen: u32) -> i64 {
    if optlen != core::mem::size_of::<i32>() as u32 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let mut bytes = [0u8; core::mem::size_of::<i32>()];
    if uaccess::copy_from_user(&mut bytes, optval).is_err() {
        return -(Errno::Efault.as_i32() as i64);
    }
    let Some(version) = parse_packet_version(&bytes, optlen as usize) else {
        return -(Errno::Einval.as_i32() as i64);
    };
    match sock.set_packet_version(version) {
        Ok(()) => 0,
        Err(error) => errno_from_neterr(error),
    }
}

fn packet_flag(sock: &Arc<net::sock::InetSocket>, optval: u64, optlen: u32,
               set: fn(&net::sock::InetSocket, bool) -> net::NetResult<()>) -> i64 {
    if optlen < core::mem::size_of::<i32>() as u32 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let mut bytes = [0u8; core::mem::size_of::<i32>()];
    if uaccess::copy_from_user(&mut bytes, optval).is_err() {
        return -(Errno::Efault.as_i32() as i64);
    }
    let Some(value) = parse_packet_flag(&bytes, optlen as usize) else {
        return -(Errno::Einval.as_i32() as i64);
    };
    match set(sock, value) {
        Ok(()) => 0,
        Err(error) => errno_from_neterr(error),
    }
}

fn packet_membership(sock: &Arc<net::sock::InetSocket>, optval: u64,
                     optlen: u32, add: bool) -> i64 {
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

fn packet_ignore_outgoing(sock: &Arc<net::sock::InetSocket>, optval: u64,
                          optlen: u32) -> i64 {
    if optlen != core::mem::size_of::<i32>() as u32 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let mut bytes = [0u8; core::mem::size_of::<i32>()];
    if uaccess::copy_from_user(&mut bytes, optval).is_err() {
        return -(Errno::Efault.as_i32() as i64);
    }
    let Some(value) = parse_packet_bool(&bytes, optlen as usize) else {
        return -(Errno::Einval.as_i32() as i64);
    };
    match sock.set_packet_ignore_outgoing(value) {
        Ok(()) => 0,
        Err(error) => errno_from_neterr(error),
    }
}
