// The keyed constructions themselves, as pure functions of (key, 4-tuple,
// clock). Port of Linux `net/core/secure_seq.c`. No globals, no clock reads,
// no target gate — every security property below is asserted in
// `secure_seq/tests.rs` against these entry points.
//
// RFC 6528 §3: ISN = M + F(localip, localport, remoteip, remoteport, secretkey)
//   M = a timer term that keeps advancing (`seq_scale`)
//   F = a *keyed* PRF over the connection identifier (`siphash`)
// Both halves are load-bearing. F alone repeats for a reused 4-tuple; M alone
// is a global sequence any observer can extrapolate from one connection to
// every other — which is exactly what a fixed start plus a fixed step is.

use siphash::{siphash, siphash_3u32, siphash_4u32, Key};

use crate::addr::{Ipv4Addr, Ipv6Addr};

/// Linux `seq_scale`: a 64 ns tick, chosen so the 32-bit sequence space wraps
/// no faster than once per 274 s — longer than the 2 min MSL, so a reused
/// 4-tuple cannot land on a sequence still live in the network.
const SEQ_TICK_SHIFT: u32 = 6;

/// Linux `EPHEMERAL_PORT_SHUFFLE_PERIOD` = 10 * HZ. The port-offset hash
/// re-shuffles this often, so a client hammering one destination does not walk
/// the port range in a fixed order, but repeated connects inside one window
/// still start from the same place (which is what makes the scan cheap).
const PORT_SHUFFLE_PERIOD_NS: u64 = 10_000_000_000;

/// Bytes of one IPv6 address, twice, plus two ports — the record Linux
/// siphashes for the v6 forms.
const V6_TUPLE_LEN: usize = 16 + 16 + 2 + 2;

/// Pack the two ports the way Linux does before hashing: `sport << 16 | dport`
/// over the on-wire (big-endian) values. # C: O(1)
#[inline]
const fn ports(sport: u16, dport: u16) -> u32 {
    ((sport.to_be() as u32) << 16) | dport.to_be() as u32
}

/// Linux `secure_tcp_seq_and_ts_off` — the raw 64-bit hash. Low half is the
/// ISN base, high half is the TCP-timestamp offset. # C: O(1)
pub(crate) fn tcp_hash64_v4(key: &Key, local: Ipv4Addr, remote: Ipv4Addr,
                            local_port: u16, remote_port: u16) -> u64 {
    siphash_3u32(local.as_u32().to_be(), remote.as_u32().to_be(),
                 ports(local_port, remote_port), key)
}

/// Linux `secure_tcpv6_seq_and_ts_off`. # C: O(1)
pub(crate) fn tcp_hash64_v6(key: &Key, local: Ipv6Addr, remote: Ipv6Addr,
                            local_port: u16, remote_port: u16) -> u64 {
    let mut buf = [0u8; V6_TUPLE_LEN];
    buf[0..16].copy_from_slice(&local.0);
    buf[16..32].copy_from_slice(&remote.0);
    buf[32..34].copy_from_slice(&local_port.to_be_bytes());
    buf[34..36].copy_from_slice(&remote_port.to_be_bytes());
    siphash(&buf, key)
}

/// Linux `seq_scale`: add the RFC 793 timer term to the keyed hash.
/// # C: O(1)
#[inline]
pub(crate) const fn seq_scale(seq: u32, now_ns: u64) -> u32 {
    seq.wrapping_add((now_ns >> SEQ_TICK_SHIFT) as u32)
}

/// Extract the ISN half of the hash and scale it. Linux `st.seq`. # C: O(1)
#[inline]
pub(crate) const fn isn_from_hash(hash64: u64, now_ns: u64) -> u32 {
    seq_scale(hash64 as u32, now_ns)
}

/// Extract the TCP-timestamp offset half. Linux `st.ts_off`. # C: O(1)
#[inline]
pub(crate) const fn ts_off_from_hash(hash64: u64) -> u32 { (hash64 >> 32) as u32 }

/// The shuffle epoch the port-offset hash is keyed on. Linux
/// `jiffies / EPHEMERAL_PORT_SHUFFLE_PERIOD`. # C: O(1)
#[inline]
pub(crate) const fn shuffle_epoch(now_ns: u64) -> u32 {
    (now_ns / PORT_SHUFFLE_PERIOD_NS) as u32
}

/// Linux `secure_ipv4_port_ephemeral`. # C: O(1)
pub(crate) fn port_offset_v4(key: &Key, local: Ipv4Addr, remote: Ipv4Addr,
                             remote_port: u16, epoch: u32) -> u64 {
    siphash_4u32(local.as_u32().to_be(), remote.as_u32().to_be(),
                 remote_port.to_be() as u32, epoch, key)
}

/// Linux `secure_ipv6_port_ephemeral`. # C: O(1)
pub(crate) fn port_offset_v6(key: &Key, local: Ipv6Addr, remote: Ipv6Addr,
                             remote_port: u16, epoch: u32) -> u64 {
    let mut buf = [0u8; 16 + 16 + 4 + 2];
    buf[0..16].copy_from_slice(&local.0);
    buf[16..32].copy_from_slice(&remote.0);
    buf[32..36].copy_from_slice(&epoch.to_ne_bytes());
    buf[36..38].copy_from_slice(&remote_port.to_be_bytes());
    siphash(&buf, key)
}

/// Linux `reciprocal_scale(val, ceil)` — map a uniform u32 into `0..ceil`
/// without a modulo bias toward the low end of the range. # C: O(1)
#[inline]
pub(crate) const fn reciprocal_scale(val: u32, ceil: u32) -> u32 {
    ((val as u64 * ceil as u64) >> 32) as u32
}
