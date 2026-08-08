// SOL_SOCKET readback copyout for slot 55. The value table and its length
// rules live in `net::sock_opts::sol_socket::get` (`docs/53§4`); this file
// only moves bytes.
#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use syscall::errno::Errno;
use net::sock::InetSocket;
use net::sock_opts::sol_socket::get::{self, SockView};

fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// The socket identity the read table needs beyond the generic base. Every
/// generic value is read straight from the base by the table itself. # C: O(1)
pub(super) fn view(sock: &Arc<InetSocket>) -> SockView {
    SockView {
        sock: net::sock_opts::describe(sock),
        acceptconn: super::socket_acceptconn(sock),
        socket_type: super::socket_type(sock),
        protocol: super::socket_protocol(sock),
        netns_cookie: net::net_ns::namespace_cookie(&sock.net_namespace),
        // No receive path in this stack runs inside a NAPI context, so no
        // socket ever records a valid identifier and the option reads zero.
        napi_id: 0,
    }
}

/// `sk_getsockopt` for one SOL_SOCKET read: import the caller length, resolve
/// one value, truncate to the natural width, then publish value and length.
/// # C: O(1)
pub(super) fn read(sock: &Arc<InetSocket>, optname: u64, optval: u64, optlen_p: u64) -> i64 {
    answer(&sock.opts.base, &view(sock), optname, optval, optlen_p)
}

/// The one SOL_SOCKET read every family uses: import the caller length,
/// resolve one value from the socket base, truncate to the natural width, then
/// publish value and length. # C: O(1)
pub(crate) fn answer(base: &net::SockBase, view: &SockView, optname: u64, optval: u64,
                     optlen_p: u64) -> i64
{
    let mut raw_len = [0u8; core::mem::size_of::<i32>()];
    if uaccess::copy_from_user(&mut raw_len, optlen_p).is_err() { return errno(Errno::Efault); }
    let requested = i32::from_ne_bytes(raw_len);
    if requested < 0 { return errno(Errno::Einval); }
    let value = match get::value(optname, requested, base, view) {
        Ok(value) => value,
        Err(e) => return errno(e),
    };
    let mut bytes = [0u8; 16];
    let natural = get::encode(&value, &mut bytes);
    let take = core::cmp::min(requested as usize, natural);
    if take != 0 && uaccess::copy_to_user(optval, &bytes[..take]).is_err() {
        return errno(Errno::Efault);
    }
    if uaccess::copy_to_user(optlen_p, &(take as u32).to_ne_bytes()).is_err() {
        return errno(Errno::Efault);
    }
    0
}

/// `SO_BINDTODEVICE` read, for every family: the answer is the bound
/// interface's name and a published length of `strlen + 1`, or an empty answer
/// of published length zero when the socket has no binding. # C: O(N ifaces)
pub(crate) fn answer_bindtodevice(base: &net::SockBase, namespace: u64, optval: u64,
                                  optlen_p: u64) -> i64
{
    let mut raw_len = [0u8; core::mem::size_of::<i32>()];
    if uaccess::copy_from_user(&mut raw_len, optlen_p).is_err() { return errno(Errno::Efault); }
    let requested = i32::from_ne_bytes(raw_len);
    if requested < 0 { return errno(Errno::Einval); }
    let name = match base.bound_device_name(namespace, requested as usize) {
        Ok(name) => name,
        Err(e) => return errno(e),
    };
    let published = match name {
        None => 0usize,
        Some(name) => {
            let mut bytes = [0u8; net::sock_opts::sol_socket::set::IFNAMSIZ];
            let text = name.as_bytes();
            let published = text.len() + 1;
            if published > bytes.len() { return errno(Errno::Einval); }
            bytes[..text.len()].copy_from_slice(text);
            if uaccess::copy_to_user(optval, &bytes[..published]).is_err() {
                return errno(Errno::Efault);
            }
            published
        }
    };
    if uaccess::copy_to_user(optlen_p, &(published as u32).to_ne_bytes()).is_err() {
        return errno(Errno::Efault);
    }
    0
}
