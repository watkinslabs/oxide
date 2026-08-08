// FLUSH decisions for a mounted fuse inode: the lock-owner scramble, the
// skip rule, and the request body layout.
//
// Kept out of `fops.rs` and free of any target gate so the three things that
// are easy to get silently wrong are hosted-testable: that the owner identity
// reaching the daemon is NOT the kernel address it was derived from, that
// `FOPEN_NOFLUSH` suppresses the request, and that the body puts `fh` and
// `lock_owner` at the offsets the protocol declares.
//
// Before this existed the FLUSH request named neither: it carried `fh = 0` and
// `lock_owner = 0` unconditionally, so a daemon could not tell WHICH open
// handle was being closed nor whose POSIX locks to drop with it.

extern crate alloc;
use alloc::vec::Vec;

use super::proto::{self, FOPEN_NOFLUSH};

/// The ENOSYS-means-unsupported classification FLUSH shares with FSYNC: a
/// daemon that declines the opcode has nothing to flush, so `close(2)` reports
/// success and the connection latches the answer. One rule, one implementation
/// — see [`super::fsync::classify_reply`].
pub use super::fsync::{classify_reply, FsyncOutcome as FlushOutcome};

/// Golden-ratio round constant of the owner-id scramble. # C: O(1)
const SCRAMBLE_DELTA: u32 = 0x9E37_79B9;
/// Rounds the scramble performs. # C: O(1)
const SCRAMBLE_ROUNDS: usize = 32;
/// Words in the per-connection scramble key. # C: O(1)
pub const SCRAMBLE_KEY_WORDS: usize = 4;

/// `fuse_flush_in.lock_owner` — the caller's lock-owner identity, scrambled
/// under this connection's random key.
///
/// The identity a flush names is a KERNEL object address (the descriptor table
/// that is closing), and the daemon is unprivileged userspace. Sending it raw
/// would hand out a kernel pointer, so the value is put through a 32-round
/// block cipher keyed per connection: the daemon still sees one stable id per
/// owner (which is all it needs to match the FLUSH against the locks that owner
/// holds), and learns nothing about the address behind it. # C: O(1)
pub fn lock_owner_id(key: &[u32; SCRAMBLE_KEY_WORDS], id: u64) -> u64 {
    let mut v0 = id as u32;
    let mut v1 = (id >> 32) as u32;
    let mut sum: u32 = 0;
    for _ in 0..SCRAMBLE_ROUNDS {
        v0 = v0.wrapping_add((((v1 << 4) ^ (v1 >> 5)).wrapping_add(v1))
                             ^ (sum.wrapping_add(key[(sum & 3) as usize])));
        sum = sum.wrapping_add(SCRAMBLE_DELTA);
        v1 = v1.wrapping_add((((v0 << 4) ^ (v0 >> 5)).wrapping_add(v0))
                             ^ (sum.wrapping_add(key[((sum >> 11) & 3) as usize])));
    }
    (v0 as u64) + ((v1 as u64) << 32)
}

/// Does this open description skip FLUSH entirely?
///
/// `FOPEN_NOFLUSH` is the daemon's own answer at OPEN time that it does not
/// want a flush on close. It is overridden by a writeback cache, because then
/// the kernel — not the daemon — holds dirty data that close must push out, so
/// the daemon's preference cannot decide the question. # C: O(1)
pub fn flush_is_skipped(open_flags: u32, writeback_cache: bool) -> bool {
    open_flags & FOPEN_NOFLUSH != 0 && !writeback_cache
}

/// Encode a `struct fuse_flush_in` (`fh,unused,padding,lock_owner`). # C: O(1)
pub fn encode_flush(out: &mut Vec<u8>, fh: u64, lock_owner: u64) {
    proto::put_u64(out, fh);
    proto::put_u32(out, 0); // unused
    proto::put_u32(out, 0); // padding
    proto::put_u64(out, lock_owner);
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::proto::FUSE_FLUSH_IN_SIZE;

    const KEY: [u32; SCRAMBLE_KEY_WORDS] = [0x1234_5678, 0x9abc_def0, 0x0f1e_2d3c, 0xdead_beef];

    /// The whole point of the scramble: the value on the wire must not BE the
    /// kernel identity it came from, for any input, including the degenerate
    /// ones. A pass-through implementation leaks a kernel address to an
    /// unprivileged daemon and this is the check that fails on it. # C: O(1)
    #[test]
    fn scramble_never_reproduces_the_kernel_identity() {
        for id in [0u64, 1, 0xffff_ffff, 0xffff_8000_1234_5678, 0xffff_ffff_ffff_ffff] {
            assert_ne!(lock_owner_id(&KEY, id), id, "identity leaked for {id:#x}");
        }
    }

    /// Distinct owners must stay distinct — the daemon matches a FLUSH against
    /// the locks of ONE owner, so a scramble that collided would drop the wrong
    /// owner's locks. The cipher is a bijection; this pins it. # C: O(N)
    #[test]
    fn scramble_is_injective_over_a_dense_range() {
        let mut seen = alloc::vec::Vec::new();
        for id in 0..512u64 {
            let s = lock_owner_id(&KEY, 0xffff_8880_0000_0000 + id * 8);
            assert!(!seen.contains(&s), "collision at {id}");
            seen.push(s);
        }
    }

    /// The key is what makes the mapping unguessable: the same owner under two
    /// connections must not present the same id, or the scramble is decoration.
    /// # C: O(1)
    #[test]
    fn scramble_depends_on_the_key() {
        let other: [u32; SCRAMBLE_KEY_WORDS] = [1, 2, 3, 4];
        let id = 0xffff_8880_1234_5678;
        assert_ne!(lock_owner_id(&KEY, id), lock_owner_id(&other, id));
    }

    /// Same key, same owner, same answer — a daemon correlates repeated FLUSHes
    /// from one owner by this id, so it cannot be per-call random. # C: O(1)
    #[test]
    fn scramble_is_stable_for_one_key_and_owner() {
        let id = 0xffff_8880_1234_5678;
        assert_eq!(lock_owner_id(&KEY, id), lock_owner_id(&KEY, id));
    }

    /// `FOPEN_NOFLUSH` suppresses the request; a writeback cache overrides the
    /// daemon's preference because the dirty data is then the kernel's.
    /// # C: O(1)
    #[test]
    fn noflush_skips_unless_a_writeback_cache_holds_the_data() {
        assert!(flush_is_skipped(FOPEN_NOFLUSH, false));
        assert!(!flush_is_skipped(FOPEN_NOFLUSH, true));
        assert!(!flush_is_skipped(0, false));
        assert!(!flush_is_skipped(0, true));
        // The bit is the protocol's, not ours to choose.
        assert_eq!(FOPEN_NOFLUSH, 1 << 5);
    }

    /// The body must put `fh` at 0 and `lock_owner` at 16 with the two middle
    /// words zeroed — an offset slip silently flushes a handle the daemon never
    /// issued. # C: O(1)
    #[test]
    fn flush_body_places_fh_and_lock_owner_at_the_declared_offsets() {
        let mut b = Vec::new();
        encode_flush(&mut b, 0x0102_0304_0506_0708, 0x1122_3344_5566_7788);
        assert_eq!(b.len(), FUSE_FLUSH_IN_SIZE);
        assert_eq!(proto::get_u64(&b, 0).unwrap(), 0x0102_0304_0506_0708);
        assert_eq!(&b[8..16], &[0, 0, 0, 0, 0, 0, 0, 0], "unused+padding must be zero");
        assert_eq!(proto::get_u64(&b, 16).unwrap(), 0x1122_3344_5566_7788);
    }

    /// The connection must draw its OWN key, so the same owner presents a
    /// different id to two daemons and never presents the kernel identity
    /// itself. A shared or zero key would make the scramble reversible.
    /// # C: O(1)
    #[test]
    fn each_connection_keys_its_own_owner_ids() {
        use super::super::conn::FuseConn;
        use alloc::sync::Arc;
        let a = FuseConn::new(Arc::new(vfs::PollSubscribers::new()));
        let b = FuseConn::new(Arc::new(vfs::PollSubscribers::new()));
        let id = 0xffff_8880_1234_5678u64;
        assert_ne!(a.lock_owner_id(id), id, "the kernel identity must not reach the daemon");
        assert_ne!(a.lock_owner_id(id), b.lock_owner_id(id), "two channels must not share a key");
        assert_eq!(a.lock_owner_id(id), a.lock_owner_id(id), "one channel's answer is stable");
    }

    /// A fresh connection has no FLUSH latch and no writeback cache, so the
    /// first close DOES send the request; the latch is set only by an actual
    /// `ENOSYS` answer. A latch that started set would silently suppress every
    /// FLUSH the daemon expects. # C: O(1)
    #[test]
    fn a_fresh_connection_sends_flush_and_latches_only_on_enosys() {
        use super::super::conn::FuseConn;
        use alloc::sync::Arc;
        let c = FuseConn::new(Arc::new(vfs::PollSubscribers::new()));
        assert!(!c.flush_unsupported());
        assert!(!c.writeback_cache(), "not negotiated at INIT, so not claimed");
        assert!(!flush_is_skipped(0, c.writeback_cache()));
        c.set_flush_unsupported();
        assert!(c.flush_unsupported());
    }

    /// The ENOSYS latch rule is the one FSYNC uses; this pins that the FLUSH
    /// path reads the same answer rather than a second copy that can drift.
    /// # C: O(1)
    #[test]
    fn enosys_is_unsupported_and_other_errnos_fail() {
        assert_eq!(classify_reply(Ok(())), FlushOutcome::Done);
        assert_eq!(classify_reply(Err(vfs::VfsError::Enosys)), FlushOutcome::Unsupported);
        assert_eq!(classify_reply(Err(vfs::VfsError::Eio)), FlushOutcome::Failed(vfs::VfsError::Eio));
    }
}
