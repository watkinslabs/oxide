// SOL_SOCKET on an AF_NETLINK fd.
//
// SOL_SOCKET never reaches a family's own option table: it is answered once,
// generically, before family dispatch, and the family op sees only its own
// level. This module is that generic step for netlink, and it owns no decision
// of its own — the argument import, the admission ladder, the capability gates
// and every value transform are the SAME ones the internet families use, so a
// write judged here cannot be judged differently there. The write itself lands in one place, the netlink socket's own
// generic option state, which is also where the read view is assembled from.

use syscall::errno::Errno;

use net::sock_opts::sol_socket::{self as sol};

use super::NetlinkFileRef;

fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// The socket personality the generic table branches on. # C: O(1)
fn personality() -> sol::OptSock { ::netlink::sol_socket::personality() }

/// Caller's network capabilities in the socket's owning namespace. # C: O(1)
fn caps_for(target: &NetlinkFileRef) -> sol::OptCaps {
    let Some(cur) = sched::live::current() else { return sol::OptCaps::default(); };
    let namespace = &target.socket().net_ns;
    sol::OptCaps {
        net_admin: nscg::has_net_admin_for(cur, namespace),
        net_raw: nscg::has_net_raw_for(cur, namespace),
    }
}

/// `sock_setsockopt` for a netlink socket. # C: O(1)
pub fn set(target: &NetlinkFileRef, optname: u64, optval: u64, optlen: u64) -> i64 {
    let socket = target.socket();
    let optlen = optlen.min(u32::MAX as u64) as u32;
    // The device binding takes a name, not an `int`, and its capability ladder
    // runs before the name is even read — the same order every family uses.
    if optname == sol::SO_BINDTODEVICE {
        return bind_to_device(target, optval, optlen);
    }
    let arg = match crate::s054_setsockopt::sol_socket::import(optname, optval, optlen) {
        Ok(arg) => arg,
        Err(e) => return errno(e),
    };
    let action = match sol::set::admit(optname, arg, personality(),
        socket.base.set_env(caps_for(target)))
    {
        Ok(action) => action,
        Err(e) => return errno(e),
    };
    match ::netlink::sol_socket::apply(socket, action) { Ok(()) => 0, Err(e) => errno(e) }
}

/// `sock_setbindtodevice` on a netlink socket. # C: O(N ifaces)
fn bind_to_device(target: &NetlinkFileRef, optval: u64, optlen: u32) -> i64 {
    let socket = target.socket();
    if let Err(e) = sol::set::bind_device_allowed(caps_for(target), socket.base.bound_device()) {
        return errno(e);
    }
    let (name, end) = match crate::s054_setsockopt::sol_socket::import_device_name(optval, optlen) {
        Ok(imported) => imported,
        Err(e) => return errno(e),
    };
    let Ok(text) = core::str::from_utf8(&name[..end]) else { return errno(Errno::Enodev); };
    match ::netlink::sol_socket::bind_to_device_name(socket, text) {
        Ok(()) => 0,
        Err(e) => errno(e),
    }
}

/// `sock_getsockopt` for a netlink socket, through the same value table every
/// other family reads. `None` when the option is not one this level answers.
/// # C: O(1)
pub fn get(target: &NetlinkFileRef, optname: u64, requested: usize)
    -> Option<Result<alloc::vec::Vec<u8>, i64>>
{
    let requested = i32::try_from(requested).unwrap_or(i32::MAX);
    let value = match ::netlink::sol_socket::read(target.socket(), optname, requested) {
        Ok(value) => value,
        Err(e) => return Some(Err(errno(e))),
    };
    let mut bytes = [0u8; 16];
    let natural = sol::get::encode(&value, &mut bytes);
    Some(Ok(bytes[..natural].to_vec()))
}
