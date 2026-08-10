// Linux `tcp_metrics`: what this host remembers about each destination it has
// spoken to, and what a connection does with that memory.
//
// A destination's round-trip time, congestion window, slow-start threshold and
// reordering degree are facts about a path, not about a connection. Keeping
// them means the second connection to a server does not have to rediscover the
// path the first one measured: it seeds its first retransmit timeout from the
// remembered round trip instead of from the handshake, whose SYN-sized samples
// are a poor guide to data behaviour.
//
// The same row also carries the fast-open state a client presents on its next
// handshake. That is not a convenience — the reference holds both in one block
// for the same reason, and splitting them would give one destination two
// homes.
//
// Module manifest:
// - `ids`: the metric slots, their netlink attribute numbers, the lock bits.
// - `store`: the cache itself — one row per address pair, per namespace.
// - `init`: what a cached row seeds into a connection that just handshook.
// - `update`: what a closing connection writes back.
// - `ns`: the namespace-facing wrappers over the cache.
//
// No target gate: every decision here is a pure function of state `cargo test`
// can build (`docs/53§4`).

pub mod ids;
pub mod init;
mod ns;
pub mod store;
pub mod update;

pub use init::{seed, CachedMetrics, Fresh, Seed, INFINITE_SSTHRESH, TIMEOUT_FALLBACK_NS};
pub use ns::{cached, cached_in, forget, forget_all, forget_all_in, peer_is_proven, pin,
    pin_in, record, record_in, row};
pub use store::{Cached, Metrics, MetricsCache, BUCKETS, ENTRY_TIMEOUT_NS, RECLAIM_DEPTH,
    TRY_EXP_ASSIGNED, TRY_EXP_EXPERIMENTAL, TRY_EXP_NONE};
pub use update::{update, Closing, Phase, Row, Update};
