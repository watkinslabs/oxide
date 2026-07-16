use alloc::sync::Arc;
use syscall::errno::Errno;

use crate::net_common::errno_from_neterr;
use super::packet_abi::{packet_rollover_statistics_bytes, packet_statistics_bytes,
                        PacketOptionValue};

/// Export one Linux AF_PACKET option with value-result length. # C: O(1)
pub(super) fn packet_getsockopt(sock: &Arc<net::sock::InetSocket>, optname: u64,
                               optval: u64, optlen_p: u64) -> i64 {
    let mut raw_len = [0u8; core::mem::size_of::<i32>()];
    if uaccess::copy_from_user(&mut raw_len, optlen_p).is_err() {
        return -(Errno::Efault.as_i32() as i64);
    }
    let requested = i32::from_ne_bytes(raw_len);
    if requested < 0 { return -(Errno::Einval.as_i32() as i64); }
    let value = match optname {
        net::uapi::PACKET_STATISTICS => packet_statistics(sock),
        net::uapi::PACKET_COPY_THRESH => packet_i32(sock.packet_copy_thresh()),
        net::uapi::PACKET_AUXDATA => packet_i32(sock.packet_auxdata().map(i32::from)),
        net::uapi::PACKET_ORIGDEV => packet_i32(sock.packet_origdev().map(i32::from)),
        net::uapi::PACKET_VERSION => packet_i32(sock.packet_version().map(i32::from)),
        net::uapi::PACKET_HDRLEN => packet_header_len(optval, requested),
        net::uapi::PACKET_RESERVE => packet_i32(
            sock.packet_reserve().map(|value| value as i32)),
        net::uapi::PACKET_LOSS => packet_i32(sock.packet_loss().map(i32::from)),
        net::uapi::PACKET_VNET_HDR => packet_i32(
            sock.packet_vnet_hdr_size().map(|size| i32::from(size != 0))),
        net::uapi::PACKET_TIMESTAMP => packet_i32(sock.packet_timestamp()),
        net::uapi::PACKET_FANOUT => packet_i32(sock.packet_fanout_value()),
        net::uapi::PACKET_TX_HAS_OFF => packet_i32(sock.packet_tx_has_off().map(i32::from)),
        net::uapi::PACKET_QDISC_BYPASS => packet_i32(
            sock.packet_qdisc_bypass().map(i32::from)),
        net::uapi::PACKET_ROLLOVER_STATS => packet_rollover_statistics(sock),
        net::uapi::PACKET_IGNORE_OUTGOING => packet_i32(
            sock.packet_ignore_outgoing().map(i32::from)),
        net::uapi::PACKET_VNET_HDR_SZ => packet_i32(
            sock.packet_vnet_hdr_size().map(|size| size as i32)),
        _ => return -(Errno::Enoprotoopt.as_i32() as i64),
    };
    let value = match value { Ok(value) => value, Err(error) => return error };
    let output = value.output(requested as usize);
    if uaccess::copy_to_user(optlen_p, &(output.len() as i32).to_ne_bytes()).is_err() {
        return -(Errno::Efault.as_i32() as i64);
    }
    if !output.is_empty() && uaccess::copy_to_user(optval, output).is_err() {
        return -(Errno::Efault.as_i32() as i64);
    }
    0
}

fn packet_header_len(optval: u64, requested: i32) -> Result<PacketOptionValue, i64> {
    if requested < 4 { return Err(-(Errno::Einval.as_i32() as i64)); }
    let mut bytes = [0u8; 4];
    if uaccess::copy_from_user(&mut bytes, optval).is_err() {
        return Err(-(Errno::Efault.as_i32() as i64));
    }
    let version = i32::from_ne_bytes(bytes);
    let value = match u8::try_from(version).ok().and_then(|version| net::sock::packet_header_len(version).ok()) {
        Some(value) => value, None => return Err(-(Errno::Einval.as_i32() as i64)),
    };
    Ok(PacketOptionValue::u32(value))
}

fn packet_rollover_statistics(sock: &net::sock::InetSocket)
    -> Result<PacketOptionValue, i64>
{
    let statistics = match sock.packet_rollover_statistics() {
        Ok(statistics) => statistics,
        Err(error) => return Err(errno_from_neterr(error)),
    };
    let value = packet_rollover_statistics_bytes(statistics);
    Ok(PacketOptionValue::from_bytes(&value))
}

fn packet_i32(value: net::NetResult<i32>) -> Result<PacketOptionValue, i64>
{
    match value {
        Ok(value) => Ok(PacketOptionValue::i32(value)),
        Err(error) => Err(errno_from_neterr(error)),
    }
}

fn packet_statistics(sock: &net::sock::InetSocket) -> Result<PacketOptionValue, i64>
{
    let (version, statistics) = match sock.take_packet_statistics() {
        Ok(value) => value,
        Err(error) => return Err(errno_from_neterr(error)),
    };
    let (value, value_len) = packet_statistics_bytes(version, statistics);
    Ok(PacketOptionValue::from_bytes(&value[..value_len]))
}
