// Packet numbers and replay detection.
//
// A replay check that is off by one accepts a frame the attacker captured and
// resent, and nothing fails: the frame decrypts, its integrity check passes
// (it is a genuine frame), and it is delivered a second time. The only thing
// standing between a link and that is the comparison in `accept`, which is
// why the counters live in their own module with their own tests rather than
// inline in each cipher.

use crate::uapi::cipher_len;

/// A 48-bit packet number, held as the integer the comparison needs rather
/// than as the six bytes the wire carries.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct Pn(pub u64);

/// Largest value a 48-bit packet number reaches. A key must be replaced
/// before its transmit counter passes this: wrapping would repeat a nonce.
pub const PN_MAX: u64 = (1u64 << 48) - 1;

impl Pn {
    /// The six wire bytes, most significant first. # C: O(1)
    pub fn to_bytes(self) -> [u8; cipher_len::CCMP_PN] {
        let v = self.0;
        [(v >> 40) as u8, (v >> 32) as u8, (v >> 24) as u8,
         (v >> 16) as u8, (v >> 8) as u8, v as u8]
    }
    /// Read a packet number from its six wire bytes. # C: O(1)
    pub fn from_bytes(b: &[u8; cipher_len::CCMP_PN]) -> Self {
        Self(((b[0] as u64) << 40) | ((b[1] as u64) << 32) | ((b[2] as u64) << 24)
             | ((b[3] as u64) << 16) | ((b[4] as u64) << 8) | b[5] as u64)
    }
    /// The next value, saturating rather than wrapping: a wrapped counter
    /// would repeat a nonce, and repeating a nonce with the same key is the
    /// one failure these ciphers cannot survive. # C: O(1)
    pub fn next(self) -> Option<Self> {
        if self.0 >= PN_MAX { None } else { Some(Self(self.0 + 1)) }
    }
}

/// The counter one key advances on transmit.
#[derive(Debug, Default)]
pub struct TxPn(u64);

impl TxPn {
    /// Start a transmit counter at a given value. # C: O(1)
    pub fn new(start: u64) -> Self { Self(start) }
    /// Take the next packet number, or nothing when the key is exhausted.
    /// # C: O(1)
    pub fn take(&mut self) -> Option<Pn> {
        let next = Pn(self.0).next()?;
        self.0 = next.0;
        Some(next)
    }
    /// Current value without advancing. # C: O(1)
    pub fn peek(&self) -> Pn { Pn(self.0) }
}

/// Traffic identifiers a replay window keeps a separate counter for, plus one
/// slot for frames that carry no traffic identifier at all. Sharing one
/// counter across identifiers rejects perfectly good frames whenever two
/// categories interleave, which is most of the time on a real link.
pub const NUM_REPLAY_SLOTS: usize = 17;
/// Slot used by a frame with no QoS control field.
pub const NON_QOS_SLOT: usize = 16;

/// The receive counters one key keeps.
#[derive(Clone, Copy, Debug)]
pub struct RxPn {
    /// Last accepted value per slot, and whether anything has been accepted.
    last: [u64; NUM_REPLAY_SLOTS],
    seen: [bool; NUM_REPLAY_SLOTS],
}

impl Default for RxPn {
    fn default() -> Self { Self { last: [0; NUM_REPLAY_SLOTS], seen: [false; NUM_REPLAY_SLOTS] } }
}

/// Slot a frame belongs in. # C: O(1)
pub fn slot(tid: Option<u8>) -> usize {
    match tid {
        Some(t) if (t as usize) < NON_QOS_SLOT => t as usize,
        _ => NON_QOS_SLOT,
    }
}

impl RxPn {
    /// Seed every slot from the value a key install supplied, so a rekeyed
    /// link does not accept the frames sent before the rekey. # C: O(slots)
    pub fn seeded(start: Pn) -> Self {
        Self { last: [start.0; NUM_REPLAY_SLOTS], seen: [start.0 != 0; NUM_REPLAY_SLOTS] }
    }

    /// Last value accepted in a slot. # C: O(1)
    pub fn last(&self, tid: Option<u8>) -> Option<Pn> {
        let i = slot(tid);
        if self.seen[i] { Some(Pn(self.last[i])) } else { None }
    }

    /// Whether a received packet number may be accepted, WITHOUT recording
    /// it. A frame is accepted only if its number is strictly greater than
    /// the last one accepted in its slot: equal is a replay of the frame
    /// itself, and lower is a replay of an older one. # C: O(1)
    pub fn would_accept(&self, tid: Option<u8>, pn: Pn) -> bool {
        let i = slot(tid);
        if !self.seen[i] { return true; }
        pn.0 > self.last[i]
    }

    /// Accept a packet number, recording it as the newest seen in its slot.
    /// Reports whether it was accepted; a rejected number leaves the slot
    /// untouched, so a replayed frame cannot advance the counter past a
    /// genuine one still in flight. # C: O(1)
    pub fn accept(&mut self, tid: Option<u8>, pn: Pn) -> bool {
        if !self.would_accept(tid, pn) { return false; }
        let i = slot(tid);
        self.last[i] = pn.0;
        self.seen[i] = true;
        true
    }

    /// Forget everything, as installing a new key does. # C: O(slots)
    pub fn reset(&mut self) { *self = Self::default(); }
}

/// The two-part counter the temporal-key cipher uses instead of a flat one:
/// the low 16 bits appear in the header before the key identifier and the
/// high 32 bits after it, and the mixing function consumes the two halves
/// separately.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Tsc {
    pub iv16: u16,
    pub iv32: u32,
}

impl Tsc {
    /// The two halves of a 48-bit counter. # C: O(1)
    pub fn from_pn(pn: Pn) -> Self {
        Self { iv16: (pn.0 & 0xffff) as u16, iv32: (pn.0 >> 16) as u32 }
    }
    /// Back to the flat counter, for comparison. # C: O(1)
    pub fn to_pn(self) -> Pn { Pn(((self.iv32 as u64) << 16) | self.iv16 as u64) }
}
