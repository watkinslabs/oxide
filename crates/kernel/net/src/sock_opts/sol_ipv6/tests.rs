// Hosted coverage for the `IPPROTO_IPV6` option table. These encode the
// verified Linux behaviour: value windows, capability ladders, errno ORDERING,
// the sticky-header shape screen and the flow-label lease rules.
//
// Module manifest: one child per behaviour group — `shape` owns operand
// widths, `values` the value windows, `ladders` the capability and state
// ladders, `sticky` the extension-header shapes, `flowlabel` the label table,
// `reads` the getsockopt answers. The shared socket personalities and the
// admission shorthand live here.

use syscall::errno::Errno;

use super::set::{self, Action, Ipv6Sock};
use super::uapi::*;
use crate::sock_opts::sol_socket::OptCaps;

mod shape;
mod values;
mod ladders;
mod sticky;
mod flowlabel;
mod reads;

fn dgram() -> Ipv6Sock { Ipv6Sock { dgram: true, protocol: IPPROTO_UDP, ..Default::default() } }
fn stream() -> Ipv6Sock { Ipv6Sock { stream: true, protocol: IPPROTO_TCP, ..Default::default() } }
fn raw(proto: u8) -> Ipv6Sock { Ipv6Sock { raw: true, protocol: proto, ..Default::default() } }
fn none() -> OptCaps { OptCaps::default() }
fn net_raw() -> OptCaps { OptCaps { net_raw: true, net_admin: false } }
fn net_admin() -> OptCaps { OptCaps { net_raw: false, net_admin: true } }

fn set6(name: u64, val: i32, len: u32) -> Result<Action, Errno> {
    set::admit(name, val, len, dgram(), none())
}
