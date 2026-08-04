// The socket-layer hop for active fast open: gathering the state one active
// open is judged against, and turning the judgement into a `connect` that
// defers, a SYN that carries data, or an ordinary handshake.
//
// The judgement itself is not here — `crate::tcp_fastopen::client::decide`
// owns it, ungated, so every rung is a `cargo test` away.

use super::{bound_iface, InetSocket};
use crate::addr::IpAddr;
use crate::tcp_conn::fastopen::Cookie;
use crate::tcp_fastopen::{self, Open, Source};

/// What the decision left for the open to carry out.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub(crate) struct ActiveOpen {
    /// The fast-open option the SYN carries.
    pub option: Option<Cookie>,
    /// The SYN carries as much of the caller's payload as fits.
    pub with_data: bool,
}

/// Judge one active open against its socket's and namespace's fast-open
/// state. `Open::Defer` means no SYN goes out at all. # C: O(log N)
pub(crate) fn plan(sock: &InetSocket, local_ip: IpAddr, remote_ip: IpAddr, source: Source)
    -> Open
{
    let namespace = &sock.owner.net_namespace;
    let now_ns = crate::tcp_conn::ka_now_ns();
    let metrics = super::stack().route_metrics_for_dst_in(
        sock.net_ns(), remote_ip, match remote_ip {
            IpAddr::V4(_) => super::iface::v4_egress_iface(sock).ok().flatten(),
            IpAddr::V6(_) => bound_iface(sock).ok().flatten(),
        });
    let pause = tcp_fastopen::blackhole_pause(namespace, now_ns);
    let cached = tcp_fastopen::cached_cookie(namespace, local_ip, remote_ip, now_ns);
    tcp_fastopen::decide_active(&tcp_fastopen::Active {
        bits: tcp_fastopen::enable_bits(namespace),
        source,
        sock_no_cookie: sock.opts.tcp.fastopen_no_cookie.load(
            ::core::sync::atomic::Ordering::Acquire),
        route_no_cookie: metrics.fastopen_no_cookie != 0,
        cached: cached.cookie,
        try_exp: cached.try_exp,
        blackholed: pause == tcp_fastopen::Pause::Held,
    })
}

/// Whether an open that just left an expired pause has to confirm it. The
/// recurrence count behind the pause is only believed until a fast open over
/// the same path succeeds with data. # C: O(log N)
pub(crate) fn confirming(sock: &InetSocket) -> bool {
    tcp_fastopen::blackhole_pause(&sock.owner.net_namespace, crate::tcp_conn::ka_now_ns())
        == tcp_fastopen::Pause::Expired
}

impl ActiveOpen {
    /// # C: O(1)
    pub(crate) fn from(open: Open) -> Self {
        Self { option: tcp_fastopen::syn_option(open), with_data: tcp_fastopen::carries_data(open) }
    }

    /// The bytes this open puts in the SYN, out of what the caller supplied.
    /// # C: O(1)
    pub(crate) fn payload<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        if self.with_data { data } else { &[] }
    }
}

#[cfg(test)]
#[path = "tcp_fastopen_tests.rs"]
mod tests;
