// What an active open does with fast open: whether the SYN waits for the
// program's first write, whether it carries data, and what its fast-open
// option says.
//
// The whole ladder is here, in one total function, for the same reason the
// listener's is (`super::server`): every rung is observable by the peer and
// none of it is transport mechanism. The governing property is the mirror of
// the listener's — **nothing on this ladder ever refuses the connection**. No
// cookie cached, a path that blackholed the last attempt, a cleared enable
// bit: each of them still opens the connection, by the ordinary three-way
// handshake, and several of them ask for a cookie on the way so the next
// connection can fast open. The program sees a working connection in every
// case; the only difference is whether its first bytes rode the SYN.
//
// Two entry points reach the ladder and they differ in one thing only. From
// `connect`, an outcome that would carry data instead becomes `Defer`: there
// is no data yet, so the SYN waits for the write that will supply it. From
// the write itself, the same outcome carries the data now.
//
// No target gate: every rung is a pure function of state `cargo test` can
// build (`docs/53§4`).

use crate::tcp_conn::fastopen::Cookie;

use super::flags::{self, TFO_CLIENT_NO_COOKIE};

/// Why a fast open did not put the program's bytes in the SYN, as
/// `TCP_INFO` reports it. `NONE` covers both a fast open that worked and a
/// connection that never attempted one.
pub const TFO_STATUS_NONE: u8 = 0;
pub const TFO_COOKIE_UNAVAILABLE: u8 = 1;
pub const TFO_DATA_NOT_ACKED: u8 = 2;
pub const TFO_SYN_RETRANSMITTED: u8 = 3;

/// Which call is asking.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Source {
    /// `connect`, on a socket carrying `TCP_FASTOPEN_CONNECT`. No payload
    /// exists yet, so an outcome that would carry data defers instead.
    Connect,
    /// The write that supplies the payload: `MSG_FASTOPEN`, or the first
    /// write after a deferred `connect`.
    Write,
}

/// One active open as the fast-open decision sees it.
pub struct Active {
    /// `net.ipv4.tcp_fastopen` in the socket's namespace.
    pub bits: i32,
    pub source: Source,
    /// `TCP_FASTOPEN_NO_COOKIE` on this socket.
    pub sock_no_cookie: bool,
    /// The route to this destination carries the no-cookie metric.
    pub route_no_cookie: bool,
    /// What the client cookie cache holds for this destination.
    pub cached: Option<Cookie>,
    /// The cache asked for the next cookie request to travel under the
    /// experimental option kind, because the assigned kind went unanswered.
    pub try_exp: bool,
    /// This namespace is inside a blackhole pause: a fast open failed here
    /// recently and active fast open is held off until the pause expires.
    pub blackholed: bool,
}

/// What the active open does.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Open {
    /// An ordinary SYN with no fast-open option at all. The connection opens
    /// the three-way way and learns nothing; this is what a blackholed path
    /// gets, so a middlebox that drops SYNs carrying options sees a SYN it
    /// will pass.
    Plain,
    /// An ordinary SYN carrying an empty fast-open option: a request for a
    /// cookie. The connection opens the three-way way and the SYN-ACK's
    /// cookie is cached for next time.
    Request { exp: bool },
    /// The SYN carries the program's data. `cookie` is the one to present, or
    /// `None` when the no-cookie rule licensed this open without one.
    Data { cookie: Option<Cookie> },
    /// No SYN yet: the socket is left waiting for the write that supplies the
    /// payload. Only ever reached from `connect`.
    Defer,
}

/// Whether a `Data` outcome carries the payload of this call rather than
/// deferring for one. # C: O(1)
fn carry(source: Source, cookie: Option<Cookie>) -> Open {
    match source {
        Source::Connect => Open::Defer,
        Source::Write => Open::Data { cookie },
    }
}

/// Decide one active open. # C: O(1)
pub fn decide(a: &Active) -> Open {
    // The path blackholed a fast open recently. The SYN goes out bare — not
    // even a cookie request — because the middlebox that ate the last one may
    // have been reacting to the option rather than to the data.
    if a.blackholed { return Open::Plain; }
    // Licensed to put data in the SYN with no cookie at all. Three
    // independent sources say so and any one is enough; the namespace bit is
    // `TFO_CLIENT_NO_COOKIE`.
    if flags::no_cookie(a.bits, TFO_CLIENT_NO_COOKIE, a.sock_no_cookie, a.route_no_cookie) {
        return carry(a.source, None);
    }
    match a.cached {
        // A cookie for this destination: the SYN may carry data and present
        // it. An empty cached value is not a cookie — it is the absence of
        // one — and falls through to asking for one.
        Some(cookie) if !cookie.is_request() => carry(a.source, Some(cookie)),
        _ => Open::Request { exp: a.try_exp },
    }
}

/// Whether an outcome puts the program's bytes in the SYN. # C: O(1)
pub fn carries_data(open: Open) -> bool { matches!(open, Open::Data { .. }) }

/// The fast-open option an outcome's SYN carries, if any. # C: O(1)
pub fn syn_option(open: Open) -> Option<Cookie> {
    match open {
        Open::Plain | Open::Defer => None,
        Open::Request { exp } => Some(Cookie::request(exp)),
        Open::Data { cookie } => cookie,
    }
}

/// What a write carrying `MSG_FASTOPEN`, or the first write after a deferred
/// `connect`, is admitted to do.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SendAdmit {
    /// Run the ladder.
    Open,
    /// This host does not do active fast open, or the call named the
    /// unspecified address — which is a disconnect request, not a
    /// destination.
    Eopnotsupp,
    /// A fast open is already in flight on this socket.
    Ealready,
}

/// Admit one fast-open write. The enable bit is read here rather than in the
/// ladder because it is the only rung that reports an error instead of
/// falling back: a program that asked for fast open by name on a host with
/// the client half turned off is told so. # C: O(1)
pub fn admit_send(bits: i32, addr_unspec: bool, in_flight: bool) -> SendAdmit {
    if !flags::client_enabled(bits) || addr_unspec { return SendAdmit::Eopnotsupp; }
    if in_flight { return SendAdmit::Ealready; }
    SendAdmit::Open
}

#[cfg(test)]
#[path = "client_tests.rs"]
mod tests;
