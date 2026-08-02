// What a listener does with the fast-open option on a SYN.
//
// The whole ladder is here, in one total function, because every rung of it is
// a decision a peer can observe and none of it is transport mechanism. The
// governing property: **nothing on this ladder ever refuses the connection**.
// A cleared enable bit, a full queue, no key, a cookie that does not verify —
// each of them falls back to an ordinary three-way handshake, and several of
// them hand the client a fresh cookie on the way so the next connection can
// fast open. A client therefore cannot tell a server that has fast open turned
// off from one whose queue is momentarily full, and never loses a connection
// over either.
//
// The queue bound is consulted before the cookie is, so a full listener spends
// no hash on a request it would decline anyway.
//
// No target gate: every rung is a pure function of state `cargo test` can
// build (`docs/53§4`).

use crate::addr::IpAddr;
use crate::tcp_conn::fastopen::{Cookie, FastOpen};

use super::cookie::{self, KeyMatch};
use super::flags::{self, TFO_SERVER_COOKIE_NOT_REQD};
use super::keys::KeyCtx;
use super::queue::FastOpenQueue;

/// One SYN as the fast-open decision sees it.
pub struct Syn {
    /// `net.ipv4.tcp_fastopen` in the listener's namespace.
    pub bits: i32,
    /// What the SYN's fast-open option said.
    pub option: FastOpen,
    /// The SYN carries payload.
    pub syn_data: bool,
    /// `TCP_FASTOPEN_NO_COOKIE` on the listening socket.
    pub sock_no_cookie: bool,
    /// The route to this peer carries the no-cookie metric.
    pub route_no_cookie: bool,
    /// Keys this listener mints and verifies with — its own if it named any,
    /// otherwise its namespace's. `None` while neither has drawn one.
    pub keys: Option<KeyCtx>,
    /// The SYN's own addresses, in the order the cookie hashes them.
    pub src: IpAddr,
    pub dst: IpAddr,
}

/// What the listener does with one SYN.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Passive {
    /// An ordinary handshake, and no fast-open option in the SYN-ACK. Any data
    /// the SYN carried is not delivered; the peer retransmits it after the
    /// handshake, which is what makes declining safe rather than lossy.
    Decline,
    /// An ordinary handshake, with this cookie in the SYN-ACK for the client
    /// to present next time.
    Offer(Cookie),
    /// The SYN's data is taken now: the child is created, the payload
    /// delivered, and the SYN-ACK acknowledges it. `reply` carries a cookie
    /// only when the client's verified under the backup key and should move to
    /// the current one.
    Accept { reply: Option<Cookie> },
}

/// Whether the option carried a value the ladder can act on. An option whose
/// length cannot be a cookie is not one: the peer meant something, but nothing
/// this side can answer, so it weighs exactly as much as no option at all.
/// # C: O(1)
fn present(option: FastOpen) -> bool {
    matches!(option, FastOpen::Request { .. } | FastOpen::Cookie(_))
}

/// The option kind the exchange is running under, so every reply keeps it.
/// # C: O(1)
fn exp_of(option: FastOpen) -> bool {
    match option {
        FastOpen::Absent => false,
        FastOpen::Request { exp } | FastOpen::Invalid { exp } => exp,
        FastOpen::Cookie(c) => c.exp,
    }
}

/// Decide one SYN, charging the queue when the answer takes its data.
/// # C: O(1)
pub fn decide(queue: &FastOpenQueue, syn: &Syn, now_ns: u64) -> Passive {
    if !flags::server_enabled(syn.bits) { return Passive::Decline; }
    // Nothing to do for a SYN that neither carries data nor says a word about
    // fast open — the ordinary handshake already handles it.
    if !(syn.syn_data || present(syn.option)) { return Passive::Decline; }
    if !queue.admit(now_ns) { return Passive::Decline; }
    let exp = exp_of(syn.option);
    if flags::no_cookie(syn.bits, TFO_SERVER_COOKIE_NOT_REQD,
        syn.sock_no_cookie, syn.route_no_cookie)
    {
        queue.hold();
        return Passive::Accept { reply: None };
    }
    // No key has been drawn, so nothing can be minted or believed. The
    // connection still proceeds, without a cookie for the client to keep.
    let Some(ctx) = syn.keys.as_ref() else { return Passive::Decline; };
    let fresh = || cookie::gen(&ctx.primary, syn.src, syn.dst, exp);
    match syn.option {
        // The client is asking for a cookie, not presenting one. It gets one
        // on the SYN-ACK and opens the ordinary way this time.
        FastOpen::Request { .. } => Passive::Offer(fresh()),
        FastOpen::Cookie(presented) => {
            match cookie::verify(ctx, syn.src, syn.dst, &presented) {
                // A cookie this side did not mint proves nothing, so the data
                // is not taken. The client is not punished for it either: it
                // gets the current cookie, which is also the repair path for a
                // client holding one from before a key rotation dropped the
                // backup.
                None => Passive::Offer(fresh()),
                Some(KeyMatch::Primary) => { queue.hold(); Passive::Accept { reply: None } }
                // Minted under the retired key. Honour it, and hand back one
                // under the current key so the next connection verifies as
                // primary and the backup can eventually be dropped.
                Some(KeyMatch::Backup) => {
                    queue.hold();
                    Passive::Accept { reply: Some(fresh()) }
                }
            }
        }
        // Data in the SYN with no usable option: the peer never proved
        // anything, so the ordinary handshake carries the connection.
        FastOpen::Absent | FastOpen::Invalid { .. } => Passive::Decline,
    }
}

#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;
