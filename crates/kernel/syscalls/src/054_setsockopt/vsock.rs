use syscall::errno::Errno;

use crate::net_errno::errno_from_neterr;

/// Parse one typed Linux `SOL_VSOCK` option from user memory. # C: O(1)
pub(super) fn vsock_setsockopt(socket: &net::vsock_socket::VsockSocket, level: u64,
    optname: u64, optval: u64, signed_optlen: i32) -> i64
{
    const VSOCK_BUFFER_OPTION_BYTES: i32 = core::mem::size_of::<u64>() as i32;
    const VSOCK_TIMEVAL_FIELD_BYTES: usize = core::mem::size_of::<i64>();
    const VSOCK_TIMEVAL_BYTES: i32 = (VSOCK_TIMEVAL_FIELD_BYTES * 2) as i32;
    if level == net::uapi::SOL_SOCKET && optname == net::uapi::SO_ZEROCOPY {
        if signed_optlen < core::mem::size_of::<i32>() as i32 {
            return -(Errno::Einval.as_i32() as i64);
        }
        let mut bytes = [0u8; core::mem::size_of::<i32>()];
        if uaccess::copy_from_user(&mut bytes, optval).is_err() {
            return -(Errno::Efault.as_i32() as i64);
        }
        return match socket.set_zerocopy(i32::from_ne_bytes(bytes)) {
            Ok(()) => 0,
            Err(e) => errno_from_neterr(e),
        };
    }
    // AF_VSOCK has no option table of its own at SOL_SOCKET: the generic
    // table answers it for every family, and the write lands on the socket
    // base. Parsing the timeouts here, as this once did, was a second copy of
    // a transform the generic owner already has — and it disagreed with it.
    if level == net::uapi::SOL_SOCKET {
        if signed_optlen < 0 { return -(Errno::Einval.as_i32() as i64); }
        return sol_socket_set(socket, optname, optval, signed_optlen as u32);
    }
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

/// `sock_setsockopt` for a virtual socket: the same import, the same admission
/// ladder and the same value transforms every other family is judged by.
/// # C: O(1)
fn sol_socket_set(socket: &net::vsock_socket::VsockSocket, optname: u64, optval: u64,
                  optlen: u32) -> i64
{
    use net::sock_opts::sol_socket as sol;
    if optname == sol::SO_BINDTODEVICE {
        if let Err(e) = sol::set::bind_device_allowed(caps_for(socket),
            socket.base.bound_device())
        { return -(e.as_i32() as i64); }
        let (name, end) = match super::sol_socket::import_device_name(optval, optlen) {
            Ok(imported) => imported,
            Err(e) => return -(e.as_i32() as i64),
        };
        let Ok(text) = core::str::from_utf8(&name[..end]) else {
            return -(Errno::Enodev.as_i32() as i64);
        };
        return match socket.sol_socket_bind_device(text) { Ok(()) => 0, Err(e) => -(e.as_i32() as i64) };
    }
    let arg = match super::sol_socket::import(optname, optval, optlen) {
        Ok(arg) => arg,
        Err(e) => return -(e.as_i32() as i64),
    };
    let action = match sol::set::admit(optname, arg, socket.sol_socket_personality(),
        socket.base.set_env(caps_for(socket)))
    {
        Ok(action) => action,
        Err(e) => return -(e.as_i32() as i64),
    };
    match socket.sol_socket_apply(action) { Ok(()) => 0, Err(e) => -(e.as_i32() as i64) }
}

/// Caller's network capabilities in the socket's owning namespace. # C: O(1)
fn caps_for(socket: &net::vsock_socket::VsockSocket) -> net::sock_opts::sol_socket::OptCaps {
    let Some(cur) = sched::live::current() else {
        return net::sock_opts::sol_socket::OptCaps::default();
    };
    let namespace = &socket.net_namespace;
    net::sock_opts::sol_socket::OptCaps {
        net_admin: nscg::has_net_admin_for(cur, namespace),
        net_raw: nscg::has_net_raw_for(cur, namespace),
    }
}
