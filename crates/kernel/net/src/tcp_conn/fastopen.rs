// Fast-open cookies: the value a server hands a client so a later connection
// may carry data in its opening SYN, and what a handshake segment's fast-open
// option means.
//
// Module manifest:
// - this file: the cookie value, the option's four possible meanings, and the
//   classification a received segment gets.
// - `tests`: the length rules and every classification.
//
// A cookie is only ever read off a SYN or a SYN-ACK. The option carries no
// cookie at all when a client is asking for one, which is a distinct meaning
// from the option being absent: absent means the peer said nothing about fast
// open, present-and-empty means it asked.
//
// No target gate: the length rules decide what a peer's segment means, so they
// live where `cargo test` compiles them (`docs/53§4`).

#[cfg(test)]
#[path = "fastopen_tests.rs"]
mod tests;

/// Shortest and longest cookie the option may carry, and the length this side
/// issues. A cookie outside the range is a malformed option rather than a
/// short one.
pub const COOKIE_MIN: usize = 4;
pub const COOKIE_MAX: usize = 16;
pub const COOKIE_SIZE: usize = 8;

/// One fast-open cookie.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Cookie {
    val: [u8; COOKIE_MAX],
    len: u8,
    /// The option travelled under the experimental kind, so a reply must use
    /// the same kind — a peer that speaks only the experimental form would not
    /// recognise the assigned one.
    pub exp: bool,
}

impl Cookie {
    /// A client's request for a cookie: the option present, carrying nothing.
    /// # C: O(1)
    pub fn request(exp: bool) -> Self { Self { val: [0; COOKIE_MAX], len: 0, exp } }

    /// A cookie of `val`, or `None` when that length cannot appear in the
    /// option. Odd lengths are excluded because the option's length byte
    /// counts a base plus the cookie, and the wire form only ever pads to an
    /// even boundary. # C: O(len)
    pub fn new(val: &[u8], exp: bool) -> Option<Self> {
        if val.len() < COOKIE_MIN || val.len() > COOKIE_MAX || val.len() % 2 != 0 { return None; }
        let mut c = Self { val: [0; COOKIE_MAX], len: val.len() as u8, exp };
        c.val[..val.len()].copy_from_slice(val);
        Some(c)
    }

    /// The cookie this side issues. Total where [`Self::new`] is not: the
    /// issued length is fixed, so a mint cannot fail the length rules and has
    /// no failure for a caller to handle. # C: O(1)
    pub fn minted(val: [u8; COOKIE_SIZE], exp: bool) -> Self {
        let mut c = Self { val: [0; COOKIE_MAX], len: COOKIE_SIZE as u8, exp };
        c.val[..COOKIE_SIZE].copy_from_slice(&val);
        c
    }

    /// # C: O(1)
    pub fn as_bytes(&self) -> &[u8] { &self.val[..self.len as usize] }

    /// # C: O(1)
    pub fn len(&self) -> usize { self.len as usize }

    /// # C: O(1)
    pub fn is_empty(&self) -> bool { self.len == 0 }

    /// Whether this is a request rather than a cookie to present. # C: O(1)
    pub fn is_request(&self) -> bool { self.len == 0 }
}

/// What a handshake segment's fast-open option says.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FastOpen {
    /// No option: the peer said nothing about fast open.
    Absent,
    /// The option is present and empty — the peer is asking for a cookie.
    Request { exp: bool },
    /// The peer presented a cookie.
    Cookie(Cookie),
    /// The option is present but its length cannot be a cookie. The peer meant
    /// something by it, so it is not the same as absent, but nothing can be
    /// done with it beyond declining to fast open.
    Invalid { exp: bool },
}

/// Classify a fast-open option body. `syn` is whether the carrying segment has
/// the SYN flag: the option is meaningless anywhere else and is ignored there
/// rather than treated as malformed.
///
/// An odd body cannot have come from a well-formed option, so it is ignored
/// entirely rather than reported — a peer that emitted one is not asking for
/// anything this side can answer. # C: O(len)
pub fn classify(body: &[u8], exp: bool, syn: bool) -> FastOpen {
    if !syn || body.len() % 2 != 0 { return FastOpen::Absent; }
    if body.is_empty() { return FastOpen::Request { exp }; }
    match Cookie::new(body, exp) {
        Some(c) => FastOpen::Cookie(c),
        None => FastOpen::Invalid { exp },
    }
}

/// Classify the fast-open option of one segment. # C: O(option_bytes)
pub fn parse(seg: &[u8], syn: bool) -> FastOpen {
    match crate::tcp_hdr::parse_fastopen_option(seg) {
        Some((body, exp)) => classify(body, exp, syn),
        None => FastOpen::Absent,
    }
}
