use syscall::errno::Errno;

use crate::net_common::errno_from_neterr;

/// Parse one typed Linux `SOL_VSOCK` option from user memory. # C: O(1)
pub(super) fn vsock_setsockopt(socket: &net::vsock_socket::VsockSocket, level: u64,
    optname: u64, optval: u64, signed_optlen: i32) -> i64
{
    const VSOCK_BUFFER_OPTION_BYTES: i32 = core::mem::size_of::<u64>() as i32;
    const VSOCK_TIMEVAL_FIELD_BYTES: usize = core::mem::size_of::<i64>();
    const VSOCK_TIMEVAL_BYTES: i32 = (VSOCK_TIMEVAL_FIELD_BYTES * 2) as i32;
    if level != net::uapi::SOL_VSOCK { return -(Errno::Enoprotoopt.as_i32() as i64); }
    if signed_optlen < 0 { return -(Errno::Einval.as_i32() as i64); }
    if net::vsock_socket::VsockSocket::is_vsock_buffer_option(optname) {
        if signed_optlen < VSOCK_BUFFER_OPTION_BYTES { return -(Errno::Einval.as_i32() as i64); }
        let mut bytes = [0u8; core::mem::size_of::<u64>()];
        if uaccess::copy_from_user(&mut bytes, optval).is_err() { return -(Errno::Efault.as_i32() as i64); }
        return match socket.set_vsock_buffer_option(optname, u64::from_ne_bytes(bytes)) {
            Ok(()) => 0,
            Err(e) => errno_from_neterr(e),
        };
    }
    if net::vsock_socket::VsockSocket::is_vsock_connect_timeout_option(optname) {
        if signed_optlen < VSOCK_TIMEVAL_BYTES { return -(Errno::Einval.as_i32() as i64); }
        let mut bytes = [0u8; VSOCK_TIMEVAL_FIELD_BYTES * 2];
        if uaccess::copy_from_user(&mut bytes, optval).is_err() { return -(Errno::Efault.as_i32() as i64); }
        let mut sec_bytes = [0u8; VSOCK_TIMEVAL_FIELD_BYTES];
        let mut usec_bytes = [0u8; VSOCK_TIMEVAL_FIELD_BYTES];
        sec_bytes.copy_from_slice(&bytes[..VSOCK_TIMEVAL_FIELD_BYTES]);
        usec_bytes.copy_from_slice(&bytes[VSOCK_TIMEVAL_FIELD_BYTES..]);
        let seconds = i64::from_ne_bytes(sec_bytes);
        let microseconds = i64::from_ne_bytes(usec_bytes);
        if seconds < 0 || microseconds < 0
            || microseconds as u64 >= net::uapi::VSOCK_MICROSECONDS_PER_SECOND {
            return -(Errno::Erange.as_i32() as i64);
        }
        let Some(timeout_ns) = (seconds as u64)
            .checked_mul(net::uapi::VSOCK_NANOSECONDS_PER_SECOND)
            .and_then(|nanos| nanos.checked_add((microseconds as u64)
                * net::uapi::VSOCK_NANOSECONDS_PER_MICROSECOND))
        else { return -(Errno::Erange.as_i32() as i64); };
        socket.set_vsock_connect_timeout_ns(timeout_ns);
        return 0;
    }
    -(Errno::Enoprotoopt.as_i32() as i64)
}
