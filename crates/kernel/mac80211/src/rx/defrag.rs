// Reassembly of fragmented frames.
//
// A fragment is only accepted into an entry whose sender, sequence number and
// NEXT EXPECTED fragment number all match. Accepting a fragment out of order,
// or from a different sender that happens to be using the same sequence
// number, is how a reassembly cache becomes a way to splice an attacker's
// bytes into somebody else's frame.

extern crate alloc;

use alloc::vec::Vec;

use wireless::ieee80211::MacAddr;

use crate::limits;

/// One partially reassembled frame.
#[derive(Clone, Debug)]
struct Entry {
    addr: MacAddr,
    seq: u16,
    /// Fragment number expected next.
    next_frag: u16,
    /// Whether the fragments so far were protected, so a mix of protected and
    /// unprotected fragments is refused rather than reassembled.
    protected: bool,
    /// Key index the accepted fragments were protected under.
    key_idx: u8,
    data: Vec<u8>,
    at_ns: u64,
}

/// The cache of frames waiting for their remaining fragments.
#[derive(Debug, Default)]
pub struct DefragCache {
    entries: Vec<Entry>,
}

/// What happened to a fragment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Defrag {
    /// Stored; nothing to deliver yet.
    Held,
    /// The frame is complete; here is its whole payload.
    Complete(Vec<u8>),
    /// The fragment does not belong to anything and is not a valid start.
    Dropped,
}

impl DefragCache {
    /// Take one fragment. `frag` is its number and `more` says whether
    /// another follows. A fragment numbered zero starts a new entry,
    /// replacing any half-finished one from the same sender — a sender that
    /// restarted has abandoned the old frame. # C: O(N entries)
    pub fn accept(&mut self, addr: MacAddr, seq: u16, frag: u16, more: bool,
                  protected: bool, key_idx: u8, payload: &[u8], now_ns: u64) -> Defrag {
        self.expire(now_ns);
        if frag == 0 {
            self.entries.retain(|e| !(e.addr == addr && e.seq == seq));
            if !more { return Defrag::Complete(payload.to_vec()); }
            if self.entries.len() >= limits::NUM_DEFRAG_ENTRIES { self.entries.remove(0); }
            self.entries.push(Entry {
                addr, seq, next_frag: 1, protected, key_idx,
                data: payload.to_vec(), at_ns: now_ns,
            });
            return Defrag::Held;
        }

        let Some(pos) = self.entries.iter().position(|e|
            e.addr == addr && e.seq == seq && e.next_frag == frag) else { return Defrag::Dropped; };
        // Every fragment of one frame must be protected the same way and
        // under the same key.
        if self.entries[pos].protected != protected || self.entries[pos].key_idx != key_idx {
            self.entries.remove(pos);
            return Defrag::Dropped;
        }
        if frag as usize >= limits::MAX_FRAGMENTS {
            self.entries.remove(pos);
            return Defrag::Dropped;
        }
        let entry = &mut self.entries[pos];
        entry.data.extend_from_slice(payload);
        entry.next_frag += 1;
        entry.at_ns = now_ns;
        if more { return Defrag::Held; }
        let done = self.entries.remove(pos);
        Defrag::Complete(done.data)
    }

    /// Drop entries whose remaining fragments never arrived. # C: O(N entries)
    pub fn expire(&mut self, now_ns: u64) {
        self.entries.retain(|e| now_ns.saturating_sub(e.at_ns) < limits::DEFRAG_TIMEOUT_NS);
    }

    /// Entries currently held. # C: O(1)
    pub fn len(&self) -> usize { self.entries.len() }
    /// Whether anything is held. # C: O(1)
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
    /// Drop everything. # C: O(1)
    pub fn clear(&mut self) { self.entries.clear(); }
}
