// F183: hosted tests for F173-F179 network correctness work.
// Catch regressions to MSS/window-scale negotiation, OOO recv
// buffering, SO_SNDBUF cap, SO_REUSEADDR conflict check, ARP
// aging, ICMP unreach handling, and output()'s multi-segment
// drain at hosted-test time — no QEMU boot required.

extern crate alloc;

use alloc::vec::Vec;
use super::*;
use crate::addr::*;
use crate::tcp_conn::{TcpConn, Endpoint};
use crate::tcp_hdr::{TcpHdr, parse_mss_option, parse_wscale_option, opt, TCP_HDR_MIN_LEN};
use crate::tcp_state::TcpState;
use crate::arp::{ArpCache, ARP_STALE_NS};
use crate::stack::NetStack;
use crate::netdev::NetError;

#[cfg(target_os = "oxide-kernel")]
#[path = "tests_perf.rs"]
mod tests_perf;
#[path = "tests_mld.rs"]
mod tests_mld;
#[path = "tests_igmp.rs"]
mod tests_igmp;
#[path = "tests_mcast_namespace_owner.rs"]
mod tests_mcast_namespace_owner;
#[path = "tests_mcast_order.rs"]
mod tests_mcast_order;
#[path = "tests_mcast_qrv.rs"]
mod tests_mcast_qrv;
#[path = "tests_mcast_queries.rs"]
mod tests_mcast_queries;
#[cfg(target_os = "oxide-kernel")]
#[path = "tests_ipv6_ext.rs"]
mod tests_ipv6_ext;

#[path = "tests_correctness/helpers.rs"]
mod helpers;
use helpers::*;
#[path = "tests_correctness/tcp_basics.rs"]
mod tcp_basics;
#[path = "tests_correctness/tcp_ipv6.rs"]
mod tcp_ipv6;
#[path = "tests_correctness/tcp_timestamps.rs"]
mod tcp_timestamps;
#[path = "tests_correctness/tcp_send.rs"]
mod tcp_send;
#[path = "tests_correctness/tcp_established.rs"]
mod tcp_established;
