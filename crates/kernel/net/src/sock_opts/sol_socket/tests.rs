// Hosted coverage for the SOL_SOCKET option table: the ordering, capability,
// value-window and length rules, encoded as the durable record of the
// verified behaviour.
//
// Module manifest: one child per option group — `basics` the identity, flag
// and generic scalars, `buffers` the send/receive sizing, `timing` the
// timeouts, linger and timestamps, `identity` the peer and device options,
// `attach` the filter, reuseport and poll-steering options.

use super::*;
use super::get::{SockView, Value};
use super::set::{Action, Arg, ArgClass, SetEnv, admit, arg_class, bind_device_allowed,
    device_name_len, devmem_dontneed_tokens};
use syscall::errno::Errno;

mod attach;
mod basics;
mod buffers;
mod identity;
mod timing;

const AF_UNIX_W: u16 = crate::socket_args::AF_UNIX as u16;
const AF_INET_W: u16 = crate::socket_args::AF_INET as u16;
const AF_NETLINK_W: u16 = crate::socket_args::AF_NETLINK as u16;
const AF_PACKET_W: u16 = crate::socket_args::AF_PACKET as u16;

fn tcp() -> OptSock { OptSock { family: AF_INET_W, stream: true, tcp: true, udp: false, peek_off_capable: false } }
fn udp() -> OptSock { OptSock { family: AF_INET_W, stream: false, tcp: false, udp: true, peek_off_capable: false } }
fn unix() -> OptSock { OptSock { family: AF_UNIX_W, stream: true, tcp: false, udp: false, peek_off_capable: true } }
fn unix_dgram() -> OptSock { OptSock { stream: false, ..unix() } }
fn packet() -> OptSock { OptSock { family: AF_PACKET_W, ..Default::default() } }

fn none() -> OptCaps { OptCaps::default() }
fn admin() -> OptCaps { OptCaps { net_admin: true, net_raw: false } }
fn raw() -> OptCaps { OptCaps { net_admin: false, net_raw: true } }

fn env(caps: OptCaps) -> SetEnv { SetEnv { caps, ..Default::default() } }

fn set(optname: u64, value: i32, sock: OptSock, caps: OptCaps) -> Result<Action, Errno> {
    admit(optname, Arg::Int(value), sock, env(caps))
}
