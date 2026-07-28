// TCP initial sequence numbers and ephemeral-port offsets — the Linux
// `net/core/secure_seq.c` owner, keyed from the one kernel CSPRNG.
//
// Module manifest:
//   `hash`    — the pure keyed constructions (RFC 6528 `F`, `seq_scale`, the
//               port-offset hash). No globals, no clock: all testable.
//   `perturb` — the connect-time port-offset perturb table
//               (Linux `table_perturb`, `net/ipv4/inet_hashtables.c`).
//
// What this replaces and why it mattered: the ISN used to be one global
// counter starting at a fixed 0x10000000 and stepping 0x1000, so every boot
// produced the same first ISN and every subsequent ISN was one addition away
// from any ISN an attacker had already seen. The passive (server) side was
// worse still — it opened at literal 0. Ephemeral ports walked the range
// sequentially from a fixed base. Together those are the two unknowns RFC 6528
// exists to protect, and an off-path attacker had to guess neither: blind RST
// and blind data injection against any TCP connection were arithmetic, not
// search.
//
// The replacement is Linux's: ISN = seq_scale(siphash(4-tuple, net_secret)).
// The 4-tuple is public, so unpredictability rests entirely on `net_secret`,
// 16 CSPRNG bytes drawn once per boot and never exposed. Knowing the ISN of
// one connection tells an attacker nothing about another's, because SipHash is
// a PRF, not a counter; and `seq_scale`'s 64 ns timer term keeps a *reused*
// 4-tuple from repeating its own ISN inside one boot.

use sync::{NetSecret as NetSecretClass, Spinlock};
use siphash::Key;

use crate::addr::IpAddr;

mod hash;
pub(crate) mod perturb;
pub(crate) mod scan;

/// Bytes drawn from the CSPRNG for the SipHash key. Linux `net_secret` is one
/// `siphash_aligned_key_t` = two u64.
const SECRET_BYTES: usize = 16;

/// Linux `net_secret`, filled by `net_get_random_once` on first use rather
/// than at init: drawing later means the CSPRNG has absorbed more entropy than
/// it had during early boot.
static NET_SECRET: Spinlock<Option<Key>, NetSecretClass> = Spinlock::new(None);

/// The boot secret, drawn on first use. # C: O(1)
fn net_secret() -> Key {
    let mut slot = NET_SECRET.lock();
    if let Some(key) = *slot { return key; }
    let mut raw = [0u8; SECRET_BYTES];
    crng::fill(&mut raw);
    let key = Key::from_bytes(&raw);
    *slot = Some(key);
    key
}

/// Discard the boot secret so the next call re-draws. Test-only: it is the
/// only way to observe "same 4-tuple, different boot" in one process.
/// # C: O(1)
#[cfg(test)]
pub(crate) fn reseed_secret_for_test() { *NET_SECRET.lock() = None; }

/// Nanosecond clock behind `seq_scale` and the port-shuffle epoch.
///
/// Linux reads `ktime_get_real_ns()`; this reads the monotonic clock, which is
/// the only one the net stack owns. The construction needs a term that only
/// ever advances at a known rate — monotonic satisfies that strictly better
/// than wall time, which `settimeofday` can move backwards.
#[cfg(target_os = "oxide-kernel")]
fn now_ns() -> u64 { crate::sock_io::monotonic_ns_safe() }

/// Hosted stand-in: tests exercise the pure layer in `hash` directly and pass
/// their own timestamps, so this only has to advance.
#[cfg(not(target_os = "oxide-kernel"))]
fn now_ns() -> u64 { crng::cycles() }

/// The initial send sequence number for one connection, in both directions:
/// Linux calls the same `secure_tcp_seq` from `tcp_v4_connect` (active open)
/// and `tcp_v4_init_seq_and_ts_off` (passive open), with the local address and
/// port first. # C: O(1)
pub(crate) fn secure_tcp_seq(local: IpAddr, remote: IpAddr,
                             local_port: u16, remote_port: u16) -> u32 {
    hash::isn_from_hash(tcp_hash64(local, remote, local_port, remote_port), now_ns())
}

/// The TCP-timestamp offset for one connection — the high half of the same
/// hash (Linux `st.ts_off`). Randomising it stops an observer correlating two
/// connections from one host by their timestamp clocks. # C: O(1)
pub(crate) fn secure_tcp_ts_off(local: IpAddr, remote: IpAddr,
                                local_port: u16, remote_port: u16) -> u32 {
    hash::ts_off_from_hash(tcp_hash64(local, remote, local_port, remote_port))
}

/// Family-dispatch for the ISN/ts-off hash. A mixed-family pair cannot name a
/// real connection; hashing it under the v6 form (after mapping) keeps the
/// function total without inventing a third construction. # C: O(1)
fn tcp_hash64(local: IpAddr, remote: IpAddr, local_port: u16, remote_port: u16) -> u64 {
    let key = net_secret();
    match (local, remote) {
        (IpAddr::V4(l), IpAddr::V4(r)) => hash::tcp_hash64_v4(&key, l, r, local_port, remote_port),
        (IpAddr::V6(l), IpAddr::V6(r)) => hash::tcp_hash64_v6(&key, l, r, local_port, remote_port),
        (l, r) => hash::tcp_hash64_v6(&key, as_v6(l), as_v6(r), local_port, remote_port),
    }
}

/// # C: O(1)
fn as_v6(ip: IpAddr) -> crate::addr::Ipv6Addr {
    match ip {
        IpAddr::V4(v4) => crate::addr::Ipv6Addr::from_v4_mapped(v4),
        IpAddr::V6(v6) => v6,
    }
}

/// Linux `inet_sk_port_offset` — the keyed starting offset for a connect-time
/// ephemeral-port scan. Same key as the ISN, different input record, so the
/// two cannot be used to solve for each other. # C: O(1)
pub(crate) fn port_offset(local: IpAddr, remote: IpAddr, remote_port: u16) -> u64 {
    let key = net_secret();
    let epoch = hash::shuffle_epoch(now_ns());
    match (local, remote) {
        (IpAddr::V4(l), IpAddr::V4(r)) => hash::port_offset_v4(&key, l, r, remote_port, epoch),
        (l, r) => hash::port_offset_v6(&key, as_v6(l), as_v6(r), remote_port, epoch),
    }
}

/// Uniform starting offset into a `count`-wide port range, for the cases with
/// no peer to key on: `bind(0)` / `listen()` (Linux `inet_csk_find_open_port`,
/// `get_random_u32_below(remaining)`) and UDP (`udp_lib_get_port`,
/// `reciprocal_scale(get_random_u32(), remaining)`). # C: O(1)
pub(crate) fn random_port_offset(count: u32) -> u32 {
    if count <= 1 { return 0; }
    hash::reciprocal_scale(crng::next_u64() as u32, count)
}

/// The candidate-port order for a connect-time auto-bind: offset keyed on the
/// 4-tuple, spread by the perturb table. Returns the bucket to charge the walk
/// back to via `perturb::record_scan`. # C: O(1)
pub(crate) fn connect_port_scan(local: IpAddr, remote: IpAddr, remote_port: u16,
                                low: u16, count: u32) -> (usize, scan::PortScan) {
    let (index, offset) = perturb::connect_offset(port_offset(local, remote, remote_port));
    (index, scan::PortScan::new(low, count, offset, scan::Parity::Connect))
}

/// The candidate-port order for `bind(0)` / `listen()`, where there is no peer
/// to key on. Linux takes a uniform random offset here rather than a keyed
/// one, and starts on the opposite parity from connect. # C: O(1)
pub(crate) fn bind_port_scan(low: u16, count: u32) -> scan::PortScan {
    scan::PortScan::new(low, count, random_port_offset(count), scan::Parity::Bind)
}

#[cfg(test)]
#[path = "secure_seq/tests.rs"]
mod tests;
