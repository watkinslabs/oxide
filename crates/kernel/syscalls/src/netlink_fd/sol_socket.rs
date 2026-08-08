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
    let arg = match crate::s054_setsockopt::sol_socket::import(optname, optval, optlen) {
        Ok(arg) => arg,
        Err(e) => return errno(e),
    };
    let env = sol::set::SetEnv {
        caps: caps_for(target),
        bound_device: false,
        ceilings: net::sysctl::buf_ceilings(),
        busy_poll_budget: socket.generic.scalar(sol::Scalar::BusyPollBudget),
    };
    let action = match sol::set::admit(optname, arg, personality(), env) {
        Ok(action) => action,
        Err(e) => return errno(e),
    };
    ::netlink::sol_socket::apply(socket, action);
    0
}

/// `sock_getsockopt` for a netlink socket, through the same value table every
/// other family reads. `None` when the option is not one this level answers.
/// # C: O(1)
pub fn get(target: &NetlinkFileRef, optname: u64, requested: usize)
    -> Option<Result<alloc::vec::Vec<u8>, i64>>
{
    let requested = i32::try_from(requested).unwrap_or(i32::MAX);
    let value = match ::netlink::sol_socket::read(target.socket(), optname, requested,
        sol::next_cookie)
    {
        Ok(value) => value,
        Err(e) => return Some(Err(errno(e))),
    };
    let mut bytes = [0u8; 16];
    let natural = sol::get::encode(&value, &mut bytes);
    Some(Ok(bytes[..natural].to_vec()))
}
