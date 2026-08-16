// Bounds, counts and durations. Every one of these is a number a link's
// behaviour depends on, and every one is named here rather than written at
// the site that uses it, because the same number is usually read by two
// modules that must agree — a window bound consulted by both ends of an
// aggregation session, a timeout consulted by both the sender and the timer
// that gives up on it.

/// One time unit in microseconds. Beacon intervals and listen intervals are
/// counted in these, not in milliseconds.
pub const TU_US: u64 = 1024;
/// Nanoseconds in one time unit.
pub const TU_NS: u64 = TU_US * 1000;

/// Convert time units to nanoseconds. # C: O(1)
pub const fn tu_to_ns(tu: u64) -> u64 { tu * TU_NS }

/// Authenticate attempts before the attempt is reported as timed out.
pub const AUTH_MAX_TRIES: u32 = 3;
/// Associate attempts before the attempt is reported as timed out.
pub const ASSOC_MAX_TRIES: u32 = 3;
/// Time one authenticate waits for its response.
pub const AUTH_TIMEOUT_NS: u64 = tu_to_ns(500);
/// Shorter wait used once a response has been seen from the peer, so a
/// retransmission is not held up by the full timeout.
pub const AUTH_TIMEOUT_SHORT_NS: u64 = tu_to_ns(100);
/// Time one associate waits for its response.
pub const ASSOC_TIMEOUT_NS: u64 = tu_to_ns(500);
pub const ASSOC_TIMEOUT_SHORT_NS: u64 = tu_to_ns(100);
/// Longest an authenticate exchange may take across all its retries.
pub const AUTH_MAX_TOTAL_NS: u64 = AUTH_TIMEOUT_NS * AUTH_MAX_TRIES as u64;

/// Beacons that may be missed in a row before the link is declared lost.
pub const BEACON_LOSS_COUNT: u32 = 7;
/// Consecutive misses after which a probe goes out rather than a disconnect,
/// so a link that is merely fading is not torn down.
pub const PROBE_START_COUNT: u32 = 3;
/// Probes sent before giving up on a link that stopped beaconing.
pub const MAX_PROBE_TRIES: u32 = 5;
/// Time one connection-monitor probe waits for its response.
pub const PROBE_WAIT_NS: u64 = tu_to_ns(500);
/// Interval at which the connection monitor runs while associated.
pub const CONNECTION_MONITOR_NS: u64 = tu_to_ns(500);
/// Default beacon interval an interface uses when nothing else asked.
pub const DEFAULT_BEACON_INT_TU: u16 = 100;
/// Default delivery-traffic-indication period.
pub const DEFAULT_DTIM_PERIOD: u8 = 2;
/// Default listen interval a station announces.
pub const DEFAULT_LISTEN_INTERVAL: u16 = 10;

/// Reorder-buffer sizes an aggregation session may agree on. Zero is not a
/// buffer, and a peer that asks for it gets the default rather than a
/// session that can never release a frame.
pub const MIN_AGG_BUF_SIZE: u16 = 1;
/// Largest buffer the plain high-throughput block ack negotiates.
pub const MAX_AGG_BUF_SIZE_HT: u16 = 64;
/// Largest buffer the extended block ack negotiates.
pub const MAX_AGG_BUF_SIZE: u16 = 1024;
/// Buffer size requested when a peer names none.
pub const DEFAULT_AGG_BUF_SIZE: u16 = 64;
/// Time a reorder buffer holds a frame behind a hole before releasing it and
/// declaring the missing frame lost. A buffer with no release timeout stalls
/// the whole traffic identifier on one dropped frame.
pub const REORDER_RELEASE_NS: u64 = 40_000_000;
/// Time an idle aggregation session is torn down after.
pub const AGG_SESSION_TIMEOUT_NS: u64 = 5_000_000_000;
/// Time an ADDBA request waits for its response before the session is
/// abandoned.
pub const ADDBA_RESP_TIMEOUT_NS: u64 = tu_to_ns(500);
/// ADDBA requests sent before the originator gives up on the peer.
pub const ADDBA_MAX_TRIES: u32 = 5;
/// Frames that must go out on a traffic identifier before the originator
/// bothers to set a session up.
pub const AGG_START_THRESHOLD: u32 = 10;

/// Duplicate-detection history depth: the last sequence-control value seen
/// per traffic identifier, plus one for the non-QoS stream.
pub const NUM_DUP_SLOTS: usize = 17;
/// Fragments one frame may be split into.
pub const MAX_FRAGMENTS: usize = 16;
/// Entries in the defragmentation cache. A cache that holds one entry drops
/// the interleaved fragments of two senders.
pub const NUM_DEFRAG_ENTRIES: usize = 4;
/// Time a partly reassembled frame waits for its missing fragments.
pub const DEFRAG_TIMEOUT_NS: u64 = 2_000_000_000;
/// Fragmentation threshold above which no fragmentation happens at all.
pub const FRAG_THRESHOLD_OFF: u32 = 2352;
/// Smallest fragmentation threshold the standard allows.
pub const MIN_FRAG_THRESHOLD: u32 = 256;
/// Request-to-send threshold above which no request-to-send is sent.
pub const RTS_THRESHOLD_OFF: u32 = 2353;

/// Stations one interface may hold before an association is refused.
pub const MAX_STATIONS: usize = 512;
/// Time a station may be silent before an access point may evict it.
pub const STA_INACTIVITY_NS: u64 = 300_000_000_000;
/// Frames buffered for one sleeping station before the oldest is dropped.
pub const MAX_PS_BUFFERED: usize = 128;
/// Time a buffered frame is held for a sleeping station.
pub const PS_BUFFER_TIMEOUT_NS: u64 = 60_000_000_000;
/// Idle time before a station in power save stops listening.
pub const DEFAULT_PS_TIMEOUT_MS: i32 = 100;
/// Beacons a station in dynamic power save stays awake for after traffic.
pub const DYNAMIC_PS_BEACONS: u32 = 2;

/// Dwell time on one channel of an active scan.
pub const SCAN_ACTIVE_DWELL_NS: u64 = tu_to_ns(30);
/// Dwell time on one channel of a passive scan — long enough to hear a
/// beacon at the default interval, which is the whole point of listening.
pub const SCAN_PASSIVE_DWELL_NS: u64 = tu_to_ns(110);
/// Probe requests sent per channel of an active scan.
pub const SCAN_PROBES_PER_CHANNEL: u32 = 2;
/// Longest a whole software scan may run before it is aborted.
pub const SCAN_MAX_TOTAL_NS: u64 = 30_000_000_000;

/// Headroom a driver gets on top of whatever it asked for: the widest
/// 802.11 header plus the widest cipher header, so no transmit path has to
/// reallocate to prepend either.
pub const TX_HEADROOM: usize = 36 + super::uapi::cipher_len::MAX_HDR;
/// Tailroom reserved for the widest integrity field.
pub const TX_TAILROOM: usize = super::uapi::cipher_len::MAX_TAIL;

/// Consecutive failures on one rate before the rate selector steps down.
pub const RATE_DOWN_FAILURES: u32 = 2;
/// Consecutive successes before it tries the next rate up.
pub const RATE_UP_SUCCESSES: u32 = 10;
/// Frames between forced probes of a higher rate, so a link that settled on
/// a low rate still discovers that conditions improved.
pub const RATE_PROBE_INTERVAL: u32 = 50;
