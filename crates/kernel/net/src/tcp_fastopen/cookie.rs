// Minting and verifying a fast-open cookie.
//
// A cookie is a keyed hash of the connection's two addresses and nothing else:
// it names the host pair, not the connection, so a client may reuse the one it
// was given on any later connection to the same server. Nothing about the
// port, the sequence number or the time enters it, which is what lets the
// server hold no per-client state at all.
//
// The key is secret and the hash is a keyed PRF, so an off-path attacker who
// knows both addresses — they are public — still cannot produce a cookie the
// server will believe. That is the whole defence: a cookie proves the client
// received an earlier reply at the address it claims.
//
// Two keys verify, one mints. A rotation installs the new key as the primary
// and keeps the old one as the backup, so cookies already in clients' hands
// keep working; a cookie that verified under the backup is answered with a
// freshly minted one so the client migrates.
//
// No target gate: the construction is the observable contract with every peer,
// so it lives where `cargo test` compiles it (`docs/53§4`).

use siphash::{siphash, Key as SipKey};

use crate::addr::IpAddr;
use crate::tcp_conn::fastopen::{Cookie, COOKIE_SIZE};

use super::keys::{Key, KeyCtx};

/// Address bytes hashed for an IPv4 pair and for an IPv6 pair.
const ADDR_BYTES_V4: usize = 8;
const ADDR_BYTES_V6: usize = 32;

/// Which key of the pair a presented cookie was minted from.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum KeyMatch {
    /// The key fresh cookies are currently minted from.
    Primary,
    /// The previous key. The connection is honoured and the client is handed a
    /// cookie under the current key so the next one verifies as primary.
    Backup,
}

/// Source address followed by destination, exactly as the packet's own network
/// header orders them. A pair that is not both IPv4 is hashed in the IPv6
/// form, so the two families can never collide on one key. # C: O(1)
fn addr_bytes(src: IpAddr, dst: IpAddr, out: &mut [u8; ADDR_BYTES_V6]) -> usize {
    if let (IpAddr::V4(s), IpAddr::V4(d)) = (src, dst) {
        out[..4].copy_from_slice(&s.octets());
        out[4..ADDR_BYTES_V4].copy_from_slice(&d.octets());
        return ADDR_BYTES_V4;
    }
    let widen = |ip: IpAddr| match ip {
        IpAddr::V6(addr) => addr,
        IpAddr::V4(addr) => crate::addr::Ipv6Addr::from_v4_mapped(addr),
    };
    out[..16].copy_from_slice(&widen(src).0);
    out[16..ADDR_BYTES_V6].copy_from_slice(&widen(dst).0);
    ADDR_BYTES_V6
}

/// The cookie this side issues for a connection between `src` and `dst` under
/// `key`. `exp` records which option kind the exchange is running under, so a
/// reply keeps the kind the peer opened with. # C: O(1)
pub fn gen(key: &Key, src: IpAddr, dst: IpAddr, exp: bool) -> Cookie {
    let mut buf = [0u8; ADDR_BYTES_V6];
    let len = addr_bytes(src, dst, &mut buf);
    let hash = siphash(&buf[..len], &SipKey::from_bytes(key.as_bytes()));
    Cookie::minted(hash.to_le_bytes(), exp)
}

/// Which key a presented cookie was minted from, if either. A cookie of any
/// length other than the one this side issues names no key: the shorter and
/// longer lengths the option permits are what another implementation may
/// issue, and this side cannot have produced them. # C: O(1)
pub fn verify(ctx: &KeyCtx, src: IpAddr, dst: IpAddr, presented: &Cookie) -> Option<KeyMatch> {
    if presented.len() != COOKIE_SIZE { return None; }
    let exp = presented.exp;
    if gen(&ctx.primary, src, dst, exp).as_bytes() == presented.as_bytes() {
        return Some(KeyMatch::Primary);
    }
    match ctx.backup {
        Some(backup) if gen(&backup, src, dst, exp).as_bytes() == presented.as_bytes() =>
            Some(KeyMatch::Backup),
        _ => None,
    }
}

#[cfg(test)]
#[path = "cookie_tests.rs"]
mod tests;
