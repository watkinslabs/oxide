// Per-connection state the DAEMON decides rather than the kernel: the
// "this opcode is not implemented" latches it teaches us one `ENOSYS` at a
// time, the features it negotiated at INIT, and the key its lock-owner ids are
// ciphered under.
//
// Split out of `conn.rs` (500-line cap) along the ownership line: `conn.rs`
// owns the request/reply channel state machine, this module owns what the
// channel has LEARNED about the peer.

use core::sync::atomic::Ordering;

use super::FuseConn;
use crate::fuse::{flush, proto};

/// Draw a fresh per-connection lock-owner scramble key from the kernel CSPRNG.
/// A fixed or predictable key would let a daemon invert the mapping and recover
/// the kernel identity the owner id is derived from. # C: O(1)
pub(super) fn random_scramble_key() -> [u32; flush::SCRAMBLE_KEY_WORDS] {
    let mut key = [0u32; flush::SCRAMBLE_KEY_WORDS];
    for w in key.iter_mut() { *w = crng::next_u64() as u32; }
    key
}

impl FuseConn {
    /// True when this daemon has already answered `ENOSYS` to the given fsync
    /// opcode, so the request must be skipped and the sync reported as done.
    /// # C: O(1)
    pub fn fsync_unsupported(&self, is_dir: bool) -> bool {
        let f = if is_dir { &self.no_fsyncdir } else { &self.no_fsync };
        f.load(Ordering::Acquire)
    }

    /// Latch the `ENOSYS` answer so no later fsync pays the round trip.
    /// # C: O(1)
    pub fn set_fsync_unsupported(&self, is_dir: bool) {
        let f = if is_dir { &self.no_fsyncdir } else { &self.no_fsync };
        f.store(true, Ordering::Release);
    }

    /// True when this daemon already answered `ENOSYS` to FLUSH, so `close(2)`
    /// must skip the request and report success. # C: O(1)
    pub fn flush_unsupported(&self) -> bool { self.no_flush.load(Ordering::Acquire) }

    /// Latch the `ENOSYS` answer so no later close pays the round trip.
    /// # C: O(1)
    pub fn set_flush_unsupported(&self) { self.no_flush.store(true, Ordering::Release); }

    /// Whether the KERNEL holds an open file's dirty data for this connection.
    /// Read from the negotiated INIT flags rather than assumed, so the day the
    /// feature is advertised the flush rule that depends on it follows without
    /// a second edit. # C: O(1)
    pub fn writeback_cache(&self) -> bool {
        self.init.lock().flags & proto::FUSE_WRITEBACK_CACHE != 0
    }

    /// The daemon-facing form of a lock-owner identity, ciphered under this
    /// connection's key so no kernel address reaches userspace. # C: O(1)
    pub fn lock_owner_id(&self, id: u64) -> u64 {
        flush::lock_owner_id(&self.scramble_key, id)
    }
}
