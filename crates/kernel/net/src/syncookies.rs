// SYN cookies: answering a connection request without remembering it.
//
// Module manifest:
//   `cookie` — the keyed construction and the MSS table. Pure.
//   `tsopt`  — the options smuggled through the timestamp echo. Pure.
//   `decide` — the three-state sysctl decision and the overflow window. Pure.
//   `overflow` — the overflow stamp cell shared by a reuseport bind key. Pure.
//   this file — the boot secret, the clock, and the namespace's sysctl.
//
// What this closes: a listener whose SYN queue was full dropped the SYN on the
// floor at every setting of `net.ipv4.tcp_syncookies`, so the sysctl was
// stored and never read. Under a flood — or merely under a burst larger than
// the backlog — legitimate connections were refused where the reference still
// completes them, which is precisely the denial of service cookies exist to
// prevent.
//
// The mechanism: instead of allocating a request, the listener answers with a
// SYN-ACK whose initial sequence number IS the state, keyed by a secret only
// this host knows. Nothing is stored, so a flood of forged SYNs costs the
// listener no memory at all. The peer's acknowledgement carries that sequence
// number back one higher, and the handshake is rebuilt from it. An off-path
// attacker cannot produce a valid one because it cannot compute the hash, and
// cannot replay an observed one because the cookie binds the 4-tuple, the
// peer's own sequence number, and the minute it was minted.
//
// No target gate on the decision modules: `docs/53§4`.

use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

use crate::addr::IpAddr;
use crate::net_ns::NetSysctlKey;

pub mod cookie;
pub mod decide;
pub mod overflow;
pub mod request;
pub mod tsopt;

pub use cookie::{Secret, MAX_SYNCOOKIE_AGE, MSSTAB_V4, MSSTAB_V6};
pub use decide::{admit, cookie_time, no_recent_overflow, restamp_overflow, Admit, ALWAYS, NEVER,
    OFF, SYNCOOKIE_VALID_NS, WHEN_FULL};
pub use request::{Rebuild, Request};
pub use tsopt::{Decoded, Permitted};

/// Secret bytes drawn for the two keys.
const SECRET_BYTES: usize = 32;

/// The two cookie keys, held in plain atomics rather than behind a lock: the
/// reader runs in softirq, where taking a lock that ranks above the CSPRNG's
/// would deadlock a CPU whose process context holds it. Same constraint, and
/// same answer, as the ISN secret in `secure_seq`.
static SECRET: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];

/// `SECRET` publication state: `UNSET` → `FILLING` (one winner) → `READY`.
static SECRET_STATE: AtomicU8 = AtomicU8::new(SECRET_UNSET);
const SECRET_UNSET: u8 = 0;
const SECRET_FILLING: u8 = 1;
const SECRET_READY: u8 = 2;

/// Draw the boot secret if it is not yet published. MUST run in process
/// context — it calls into the CSPRNG. A SYN cannot arrive for a listener that
/// was never bound, and bind primes this, so the softirq reader always finds
/// it ready. # C: O(1)
pub fn prime() {
    if SECRET_STATE.load(Ordering::Acquire) == SECRET_READY { return; }
    if SECRET_STATE.compare_exchange(SECRET_UNSET, SECRET_FILLING,
        Ordering::AcqRel, Ordering::Acquire).is_err() { return; }
    let mut raw = [0u8; SECRET_BYTES];
    crng::fill(&mut raw);
    let secret = Secret::from_bytes(&raw);
    SECRET[0].store(secret.first.k0, Ordering::Relaxed);
    SECRET[1].store(secret.first.k1, Ordering::Relaxed);
    SECRET[2].store(secret.second.k0, Ordering::Relaxed);
    SECRET[3].store(secret.second.k1, Ordering::Relaxed);
    SECRET_STATE.store(SECRET_READY, Ordering::Release);
}

/// The boot secret. Lock-free and safe from softirq. # C: O(1)
pub fn secret() -> Secret {
    if SECRET_STATE.load(Ordering::Acquire) != SECRET_READY { prime(); }
    Secret {
        first: siphash::Key { k0: SECRET[0].load(Ordering::Relaxed),
                              k1: SECRET[1].load(Ordering::Relaxed) },
        second: siphash::Key { k0: SECRET[2].load(Ordering::Relaxed),
                               k1: SECRET[3].load(Ordering::Relaxed) },
    }
}

/// `net.ipv4.tcp_syncookies` for a live namespace. A namespace with no
/// materialised state has not changed the knob, so it is judged by the same
/// default a fresh one carries. # C: O(log N)
pub fn mode_in(net_ns: u64) -> i64 {
    crate::sysctl::value_in(net_ns, NetSysctlKey::TcpSyncookies).unwrap_or(WHEN_FULL)
}

/// The initial sequence number to answer this SYN with, and the MSS the
/// rebuilt connection will believe the peer announced. Addresses and ports are
/// the arriving packet's own, in its own order. # C: O(1)
#[allow(clippy::too_many_arguments)]
pub fn init_sequence(src: IpAddr, dst: IpAddr, sport: u16, dport: u16, seq: u32,
                     now_ns: u64, ipv6: bool, mss: u16) -> (u32, u16)
{
    cookie::init_sequence(&secret(), src, dst, sport, dport, seq,
                          cookie_time(now_ns), ipv6, mss)
}

/// The MSS a returning acknowledgement's cookie encodes, or `None` when it
/// carries none this host minted. # C: O(1)
#[allow(clippy::too_many_arguments)]
pub fn validate(src: IpAddr, dst: IpAddr, sport: u16, dport: u16, seq: u32, ack: u32,
                now_ns: u64, ipv6: bool) -> Option<u16>
{
    cookie::validate(&secret(), src, dst, sport, dport, seq, ack,
                     cookie_time(now_ns), ipv6)
}

#[cfg(test)]
#[path = "syncookies/tests.rs"]
mod tests;
