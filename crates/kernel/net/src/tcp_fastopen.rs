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
// - `client`: what an active open does — whether the SYN waits for the first
//   write, whether it carries data, and what its option says.
// - `learn`: what the SYN-ACK answering an active open teaches.
// - `cache`: the cookies this host learned, per destination.
// - `blackhole`: the namespace-wide pause on active fast open after a path
//   ate one.
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

mod blackhole;
mod cache;
mod client;
mod cookie;
mod flags;
mod keys;
mod learn;
mod ns;
mod queue;
mod server;

pub use blackhole::{detect, pause_at, pause_ns, Blackhole, Pause};
pub use cache::{Cached, ClientCache, Metrics, BUCKETS, ENTRY_TIMEOUT_NS, RECLAIM_DEPTH,
    TRY_EXP_ASSIGNED, TRY_EXP_EXPERIMENTAL, TRY_EXP_NONE};
pub use client::{admit_send, carries_data, decide as decide_active, syn_option, Active, Open,
    SendAdmit, Source, TFO_COOKIE_UNAVAILABLE, TFO_DATA_NOT_ACKED, TFO_STATUS_NONE,
    TFO_SYN_RETRANSMITTED};
pub use cookie::{gen, verify, KeyMatch};
pub use flags::{client_enabled, no_cookie, server_enabled, BLACKHOLE_TIMEOUT_DEFAULT, TFO_CLIENT_ENABLE,
    TFO_CLIENT_NO_COOKIE, TFO_DEFAULT, TFO_SERVER_COOKIE_NOT_REQD, TFO_SERVER_ENABLE,
    TFO_SERVER_WO_SOCKOPT1};
pub use keys::{format_hex, parse_hex, Key, KeyCtx, KEY_BUF_LEN, KEY_LEN};
pub use learn::{learn, Learned, Synack};
pub use ns::{blackhole_disable, blackhole_pause, blackhole_reset, blackhole_timeout,
    blackhole_times, cache_learned, cached_cookie, enable_bits, enable_bits_in, init_key_once,
    cache_metrics, ns_keys, set_ns_keys, NsKeys};
pub use queue::{clamp_qlen, on_listen, Admission, FastOpenQueue, RST_PENALTY_NS};
pub use server::{decide, decide_counted, Counter, Decision, Passive, Syn};
