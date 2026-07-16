use alloc::sync::Arc;
use syscall::errno::Errno;

use crate::net_common::errno_from_neterr;
use super::packet_abi::packet_i32_copy_len;

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
    let (result, output_len) = match optname {
        net::uapi::PACKET_AUXDATA => packet_bool(sock.packet_auxdata(), optval, take, requested),
        net::uapi::PACKET_ORIGDEV => packet_bool(sock.packet_origdev(), optval, take, requested),
        net::uapi::PACKET_IGNORE_OUTGOING => packet_bool(
            sock.packet_ignore_outgoing(), optval, take, requested),
        _ => (-(Errno::Enoprotoopt.as_i32() as i64), requested as u32),
    };
    if uaccess::copy_to_user(optlen_p, &output_len.to_ne_bytes()).is_err() {
        return -(Errno::Efault.as_i32() as i64);
    }
    result
}

fn packet_bool(value: net::NetResult<bool>, optval: u64, take: usize, requested: i32)
    -> (i64, u32)
{
    match value {
            Ok(enabled) => {
                let value = i32::from(enabled).to_ne_bytes();
                if take != 0 && uaccess::copy_to_user(optval, &value[..take]).is_err() {
                    return (-(Errno::Efault.as_i32() as i64), take as u32);
                }
                (0, take as u32)
            }
            Err(error) => (errno_from_neterr(error), requested as u32),
    }
}
