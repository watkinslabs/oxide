// What the SYN-ACK teaches a client that fast-opened, or tried to.
//
// Three separable things come back on one segment: a cookie to keep, evidence
// about whether the path carries fast-open SYNs at all, and whether this
// connection's data survived. They are decided together because each is
// conditioned on the others — an unsolicited cookie is ignored, a missing
// cookie means something different before and after a SYN retransmit, and the
// request kind is only worth changing while no cookie is held.
//
// Every outcome here leaves a working connection. When the data did not
// survive, it is still in the retransmit queue and goes out again on the
// ordinary path; the connection is established either way and the program
// never sees the difference.
//
// No target gate: the rules decide what a later connection may do, so they
// live where `cargo test` compiles them (`docs/53§4`).

use crate::tcp_conn::fastopen::Cookie;

use super::cache::{TRY_EXP_ASSIGNED, TRY_EXP_EXPERIMENTAL, TRY_EXP_NONE};
use super::client::{TFO_DATA_NOT_ACKED, TFO_STATUS_NONE, TFO_SYN_RETRANSMITTED};

/// One SYN-ACK answering an active open.
pub struct Synack {
    /// The SYN carried a fast-open option — a cookie or a request for one.
    pub syn_fastopen: bool,
    /// That option travelled under the experimental kind.
    pub syn_fastopen_exp: bool,
    /// The SYN carried the program's data.
    pub syn_data: bool,
    /// SYN retransmits before this answer arrived. A retransmitted SYN
    /// carries no fast-open option, so an answer to one says nothing about
    /// whether the server would have honoured the original.
    pub total_retrans: u32,
    /// The fast-open option on the SYN-ACK.
    pub cookie: Option<Cookie>,
    /// The acknowledgement covered the data the SYN carried.
    pub data_acked: bool,
}

/// What the answer changes.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Learned {
    /// The cookie to record for this destination, if any.
    pub cookie: Option<Cookie>,
    /// The fast-open SYN went unanswered and the peer only ever saw a
    /// retransmitted, ordinary one — evidence the path drops SYNs carrying
    /// data.
    pub syn_lost: bool,
    /// The option kind the next cookie request to this destination should
    /// use.
    pub try_exp: u8,
    /// The data in the SYN was not taken. It is still owed to the peer and
    /// goes out on the ordinary retransmit path.
    pub failed: bool,
    /// The data in the SYN was taken: a fast open that worked end to end.
    pub data_acked: bool,
    /// Why the fast open did not take, as `TCP_INFO` reports it.
    pub client_fail: u8,
}

/// Read one SYN-ACK. # C: O(1)
pub fn learn(s: &Synack) -> Learned {
    // A cookie this side never asked for is not evidence of anything, and
    // recording it would let any peer seed the cache.
    let cookie = if s.syn_fastopen { s.cookie.filter(|c| !c.is_request()) } else { None };
    let failed = s.syn_data && !s.data_acked;
    let syn_lost = s.syn_fastopen && s.total_retrans > 0 && cookie.is_none() && failed;
    // A cookie was asked for and not given, on the first try, by a peer that
    // took no data. Nothing distinguishes a server that does not do fast open
    // from a middlebox that ate the option, so the next request goes out
    // under the other option kind.
    let try_exp = if s.syn_fastopen && s.total_retrans == 0 && cookie.is_none() && !s.syn_data {
        if s.syn_fastopen_exp { TRY_EXP_ASSIGNED } else { TRY_EXP_EXPERIMENTAL }
    } else { TRY_EXP_NONE };
    let client_fail = if !failed { TFO_STATUS_NONE }
        else if s.total_retrans > 0 { TFO_SYN_RETRANSMITTED } else { TFO_DATA_NOT_ACKED };
    Learned { cookie, syn_lost, try_exp, failed, data_acked: s.syn_data && s.data_acked,
        client_fail }
}

#[cfg(test)]
#[path = "learn_tests.rs"]
mod tests;
