use alloc::sync::Arc;
use syscall::errno::Errno;

use crate::net_common::errno_from_neterr;
use super::packet_abi::{packet_i32_copy_len, packet_rollover_statistics_bytes,
                        packet_statistics_bytes};

/// Export one Linux AF_PACKET option with value-result length. # C: O(1)
pub(super) fn packet_getsockopt(sock: &Arc<net::sock::InetSocket>, optname: u64,
                               optval: u64, optlen_p: u64) -> i64 {
    let mut raw_len = [0u8; core::mem::size_of::<i32>()];
    if uaccess::copy_from_user(&mut raw_len, optlen_p).is_err() {
        return -(Errno::Efault.as_i32() as i64);
    }
    let requested = i32::from_ne_bytes(raw_len);
    let Some(take) = packet_i32_copy_len(requested) else {
        return -(Errno::Einval.as_i32() as i64);
    };
    if optname == net::uapi::PACKET_HDRLEN {
        return packet_header_len(optval, optlen_p, requested);
    }
    let (result, output_len) = match optname {
        net::uapi::PACKET_STATISTICS => packet_statistics(sock, optval, requested),
        net::uapi::PACKET_AUXDATA => packet_i32(
            sock.packet_auxdata().map(i32::from), optval, take, requested),
        net::uapi::PACKET_ORIGDEV => packet_i32(
            sock.packet_origdev().map(i32::from), optval, take, requested),
        net::uapi::PACKET_VERSION => packet_i32(
            sock.packet_version().map(i32::from), optval, take, requested),
        net::uapi::PACKET_RESERVE => packet_i32(
            sock.packet_reserve().map(|value| value as i32), optval, take, requested),
        net::uapi::PACKET_LOSS => packet_i32(
            sock.packet_loss().map(i32::from), optval, take, requested),
        net::uapi::PACKET_FANOUT => packet_i32(
            sock.packet_fanout_value(), optval, take, requested),
        net::uapi::PACKET_ROLLOVER_STATS =>
            packet_rollover_statistics(sock, optval, requested),
        net::uapi::PACKET_IGNORE_OUTGOING => packet_i32(
            sock.packet_ignore_outgoing().map(i32::from), optval, take, requested),
        _ => (-(Errno::Enoprotoopt.as_i32() as i64), requested as u32),
    };
    if uaccess::copy_to_user(optlen_p, &output_len.to_ne_bytes()).is_err() {
        return -(Errno::Efault.as_i32() as i64);
    }
    result
}

fn packet_header_len(optval: u64, optlen_p: u64, requested: i32) -> i64 {
    if requested < 4 { return -(Errno::Einval.as_i32() as i64); }
    let mut bytes = [0u8; 4];
    if uaccess::copy_from_user(&mut bytes, optval).is_err() {
        return -(Errno::Efault.as_i32() as i64);
    }
    let version = i32::from_ne_bytes(bytes);
    let value = match u8::try_from(version).ok().and_then(|version| net::sock::packet_header_len(version).ok()) {
        Some(value) => value, None => return -(Errno::Einval.as_i32() as i64),
    };
    if uaccess::copy_to_user(optlen_p, &4u32.to_ne_bytes()).is_err() {
        return -(Errno::Efault.as_i32() as i64);
    }
    if uaccess::copy_to_user(optval, &value.to_ne_bytes()).is_err() {
        return -(Errno::Efault.as_i32() as i64);
    }
    0
}

fn packet_rollover_statistics(sock: &net::sock::InetSocket, optval: u64, requested: i32)
    -> (i64, u32)
{
    let statistics = match sock.packet_rollover_statistics() {
        Ok(statistics) => statistics,
        Err(error) => return (errno_from_neterr(error), requested as u32),
    };
    let value = packet_rollover_statistics_bytes(statistics);
    let take = core::cmp::min(requested as usize, value.len());
    if take != 0 && uaccess::copy_to_user(optval, &value[..take]).is_err() {
        return (-(Errno::Efault.as_i32() as i64), take as u32);
    }
    (0, take as u32)
}

fn packet_i32(value: net::NetResult<i32>, optval: u64, take: usize, requested: i32)
    -> (i64, u32)
{
    match value {
            Ok(value) => {
                let value = value.to_ne_bytes();
                if take != 0 && uaccess::copy_to_user(optval, &value[..take]).is_err() {
                    return (-(Errno::Efault.as_i32() as i64), take as u32);
                }
                (0, take as u32)
            }
            Err(error) => (errno_from_neterr(error), requested as u32),
    }
}

fn packet_statistics(sock: &net::sock::InetSocket, optval: u64, requested: i32)
    -> (i64, u32)
{
    let (version, statistics) = match sock.take_packet_statistics() {
        Ok(value) => value,
        Err(error) => return (errno_from_neterr(error), requested as u32),
    };
    let (value, value_len) = packet_statistics_bytes(version, statistics);
    let take = core::cmp::min(requested as usize, value_len);
    if take != 0 && uaccess::copy_to_user(optval, &value[..take]).is_err() {
        return (-(Errno::Efault.as_i32() as i64), take as u32);
    }
    (0, take as u32)
}
