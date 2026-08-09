// The cookie construction itself, as a pure function of (secret, 4-tuple,
// peer sequence, minute counter, MSS). No globals, no clock, no target gate:
// every property below is asserted in `cookie_tests.rs` against these entry
// points.
//
// A cookie replaces the half-open request the listener would otherwise have
// stored. Everything the handshake needs to be rebuilt from the returning
// acknowledgement has to travel in the 32 bits of the initial sequence number
// this side sends, and nothing may be remembered:
//
//   cookie = H0(tuple) + peer_isn + (count << 24)
//            + ((H1(tuple, count) + mss_index) & 0xffffff)
//
// The two hashes are keyed by two independent secrets. `H0` binds the cookie
// to the 4-tuple and the peer's own sequence number, so a cookie minted for
// one connection cannot be replayed onto another. `count` is a minute counter,
// carried in the top 8 bits it survives, which is what bounds a cookie's life:
// validation recovers the counter the cookie was minted under and refuses one
// older than `MAX_SYNCOOKIE_AGE` minutes. `H1` is what conceals the payload —
// the MSS-table index added into the low 24 bits — from anyone without the
// secret, so the low bits cannot be forged.
//
// The MSS is not carried literally. Four bits would not hold it and there is
// no room for sixteen, so the SYN's advertised MSS is rounded DOWN to one of
// four table entries and only the index travels. Rounding down is deliberate:
// the rebuilt connection must never believe the peer accepts a larger segment
// than it announced.

use siphash::{siphash, siphash_4u32, Key};

use crate::addr::{IpAddr, Ipv6Addr};

/// Bits of the cookie the minute counter occupies, at the top.
pub const COOKIEBITS: u32 = 24;
/// The low bits the concealed payload occupies.
pub const COOKIEMASK: u32 = (1u32 << COOKIEBITS) - 1;
/// Minute counters a cookie may lag the current one by and still validate. A
/// cookie is therefore good for at most two minutes, and for less than that
/// when the counter advances right after it is minted.
pub const MAX_SYNCOOKIE_AGE: u32 = 2;

/// IPv4 MSS table. Sorted, and chosen so the common announced values round to
/// themselves: 1460 is by far the most frequently announced, 1440/1452 is what
/// PPPoE leaves, 1300 covers the tunnelled range and 536 is the floor.
pub const MSSTAB_V4: [u16; 4] = [536, 1300, 1440, 1460];

/// IPv6 MSS table. The v6 minimum MTU is 1280 and the header pair costs 60, so
/// the floor is higher than v4's; the top entry is a jumbo frame.
pub const MSSTAB_V6: [u16; 4] = [1280 - 60, 1480 - 60, 1500 - 60, 9000 - 60];

/// Bytes of the record the IPv6 form hashes: two addresses, the counter, two
/// ports.
const V6_RECORD_LEN: usize = 16 + 16 + 4 + 2 + 2;

/// The two independent keys a cookie is built from. `first` binds the tuple,
/// `second` conceals the payload; one key for both would let the payload be
/// solved for out of the tuple term.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Secret {
    pub first: Key,
    pub second: Key,
}

impl Secret {
    /// Split 32 secret bytes into the two keys. # C: O(1)
    pub fn from_bytes(raw: &[u8; 32]) -> Self {
        let mut lo = [0u8; 16];
        let mut hi = [0u8; 16];
        lo.copy_from_slice(&raw[..16]);
        hi.copy_from_slice(&raw[16..]);
        Self { first: Key::from_bytes(&lo), second: Key::from_bytes(&hi) }
    }
}

/// The MSS table for one address family. # C: O(1)
pub const fn msstab(ipv6: bool) -> &'static [u16] {
    if ipv6 { &MSSTAB_V6 } else { &MSSTAB_V4 }
}

/// Index of the largest table entry not exceeding `mss`, or 0 when `mss` is
/// below the floor. Rounding down is what keeps the rebuilt connection from
/// sending segments the peer never said it would accept. # C: O(table)
pub fn mss_index(mss: u16, tab: &[u16]) -> usize {
    let mut index = tab.len() - 1;
    while index > 0 {
        if mss >= tab[index] { break; }
        index -= 1;
    }
    index
}

/// The two ports packed the way the reference packs them before hashing:
/// source in the high half, destination in the low, over the on-wire values.
/// # C: O(1)
#[inline]
const fn ports(sport: u16, dport: u16) -> u32 {
    ((sport.to_be() as u32) << 16) | dport.to_be() as u32
}

/// # C: O(1)
fn as_v6(ip: IpAddr) -> Ipv6Addr {
    match ip {
        IpAddr::V4(v4) => Ipv6Addr::from_v4_mapped(v4),
        IpAddr::V6(v6) => v6,
    }
}

/// One keyed term over the packet's own (source, destination) pair and the
/// minute counter. A pair that is not both IPv4 is hashed in the IPv6 record,
/// so the two families can never collide under one key. # C: O(1)
fn cookie_hash(key: &Key, src: IpAddr, dst: IpAddr, sport: u16, dport: u16, count: u32) -> u32 {
    if let (IpAddr::V4(s), IpAddr::V4(d)) = (src, dst) {
        return siphash_4u32(s.as_u32().to_be(), d.as_u32().to_be(),
                            ports(sport, dport), count, key) as u32;
    }
    let mut buf = [0u8; V6_RECORD_LEN];
    buf[0..16].copy_from_slice(&as_v6(src).0);
    buf[16..32].copy_from_slice(&as_v6(dst).0);
    buf[32..36].copy_from_slice(&count.to_ne_bytes());
    buf[36..38].copy_from_slice(&sport.to_be_bytes());
    buf[38..40].copy_from_slice(&dport.to_be_bytes());
    siphash(&buf, key) as u32
}

/// Mint a cookie carrying `data` in its concealed low bits. # C: O(1)
#[allow(clippy::too_many_arguments)]
pub fn mint(secret: &Secret, src: IpAddr, dst: IpAddr, sport: u16, dport: u16,
            peer_isn: u32, count: u32, data: u32) -> u32
{
    let bind = cookie_hash(&secret.first, src, dst, sport, dport, 0);
    let conceal = cookie_hash(&secret.second, src, dst, sport, dport, count);
    bind.wrapping_add(peer_isn)
        .wrapping_add(count.wrapping_shl(COOKIEBITS))
        .wrapping_add(conceal.wrapping_add(data) & COOKIEMASK)
}

/// Recover the concealed payload, or `None` when the cookie was not minted by
/// this host for this 4-tuple and peer sequence, or was minted too long ago.
///
/// A payload that survives this is still only 24 bits wide, so a forged cookie
/// has a chance of decoding to *some* value: the caller must range-check what
/// it gets, which for the MSS index is what [`validate`] does. # C: O(1)
#[allow(clippy::too_many_arguments)]
pub fn check(secret: &Secret, src: IpAddr, dst: IpAddr, sport: u16, dport: u16,
             peer_isn: u32, cookie: u32, count: u32) -> Option<u32>
{
    let bind = cookie_hash(&secret.first, src, dst, sport, dport, 0);
    let stripped = cookie.wrapping_sub(bind.wrapping_add(peer_isn));
    // What is left is (count << 24) plus the concealed payload. The counter
    // only survives in eight bits, so the difference is taken in eight bits.
    let diff = count.wrapping_sub(stripped >> COOKIEBITS) & (u32::MAX >> COOKIEBITS);
    if diff >= MAX_SYNCOOKIE_AGE { return None; }
    let conceal = cookie_hash(&secret.second, src, dst, sport, dport, count.wrapping_sub(diff));
    Some(stripped.wrapping_sub(conceal) & COOKIEMASK)
}

/// The initial sequence number to answer a SYN with, and the MSS the rebuilt
/// connection will believe the peer announced — the SYN's own MSS rounded down
/// to the table. `seq` is the SYN's sequence number. # C: O(1)
#[allow(clippy::too_many_arguments)]
pub fn init_sequence(secret: &Secret, src: IpAddr, dst: IpAddr, sport: u16, dport: u16,
                     seq: u32, count: u32, ipv6: bool, mss: u16) -> (u32, u16)
{
    let tab = msstab(ipv6);
    let index = mss_index(mss, tab);
    (mint(secret, src, dst, sport, dport, seq, count, index as u32), tab[index])
}

/// The MSS a returning acknowledgement's cookie encodes, or `None` when it
/// carries no cookie this host minted. `seq`/`ack` are the acknowledgement's
/// own header fields: the cookie is the sequence number this side sent, so it
/// is one below the acknowledgement, and the peer's own initial sequence
/// number is one below the segment's sequence. # C: O(1)
#[allow(clippy::too_many_arguments)]
pub fn validate(secret: &Secret, src: IpAddr, dst: IpAddr, sport: u16, dport: u16,
                seq: u32, ack: u32, count: u32, ipv6: bool) -> Option<u16>
{
    let data = check(secret, src, dst, sport, dport,
                     seq.wrapping_sub(1), ack.wrapping_sub(1), count)?;
    msstab(ipv6).get(data as usize).copied()
}
