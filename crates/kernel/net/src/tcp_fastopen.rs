// Fast-open policy: who is allowed to fast open, and the keys the cookies are
// minted from. The wire codec — what a handshake segment's fast-open option
// says and how it is laid out — is `tcp_conn::fastopen`; this module owns the
// state that decides whether that option is ever produced or believed.
//
// Module manifest:
// - `flags`: the `net.ipv4.tcp_fastopen` enable bits and the decisions gated
//   on them.
// - `keys`: the key pair an owner mints cookies from, and the text form the
//   sysctl leaf reads and writes.
// - `cookie`: the cookie construction itself — mint under one key, verify
//   against the pair.
// - `server`: what a listener does with the fast-open option on a SYN.
// - `queue`: the per-accept-queue fast-open state — the bound on outstanding
//   fast-open requests and this listener's own keys.
// - `ns`: the namespace-wide half — the enable bits and the default keys every
//   listener that named none of its own falls back to.
//
// Ownership: the enable bits and the default keys are namespace state, not
// socket state; the queue bound and any listener-specific key are accept-queue
// state, not a per-socket option value. A socket accepted from a listener
// inherits neither, because its accept queue is a fresh one.
//
// No target gate: every decision here is a pure function of state `cargo test`
// can build (`docs/53§4`).

mod cookie;
mod flags;
mod keys;
mod ns;
mod queue;
mod server;

pub use cookie::{gen, verify, KeyMatch};
pub use flags::{client_enabled, no_cookie, server_enabled, TFO_CLIENT_ENABLE,
    TFO_CLIENT_NO_COOKIE, TFO_DEFAULT, TFO_SERVER_COOKIE_NOT_REQD, TFO_SERVER_ENABLE,
    TFO_SERVER_WO_SOCKOPT1};
pub use keys::{format_hex, parse_hex, Key, KeyCtx, KEY_BUF_LEN, KEY_LEN};
pub use ns::{enable_bits, enable_bits_in, init_key_once, ns_keys, set_ns_keys, NsKeys};
pub use queue::{clamp_qlen, on_listen, FastOpenQueue, RST_PENALTY_NS};
pub use server::{decide, Passive, Syn};
