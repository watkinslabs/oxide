// Netlink multicast-group subscription bitmap.
//
// A netlink socket subscribes to broadcast groups by NUMBER (1-based). Linux
// keeps the subscription in a growable `unsigned long` bitmap sized by the
// protocol's `ngroups`, and `bind`'s `nl_groups` only ever writes the LOW 32
// bits — every higher group is reachable through `NETLINK_ADD_MEMBERSHIP`
// alone. `NETLINK_LIST_MEMBERSHIPS` copies the bitmap out as `u32` words.

extern crate alloc;

use alloc::vec::Vec;

use sync::{Socket as SockLockClass, Spinlock};

/// Bits per exported bitmap word — the `NETLINK_LIST_MEMBERSHIPS` granularity.
pub const GROUP_BITS_PER_WORD: u32 = 32;

/// Group count of a protocol whose kernel socket asked for fewer: netlink
/// rounds every protocol up to a full word of subscribable groups.
pub const NETLINK_MIN_NGROUPS: u32 = 32;

/// Highest `RTNLGRP_*` group id a `NETLINK_ROUTE` socket may subscribe to.
pub const RTNLGRP_MAX: u32 = 39;

/// Growable multicast-group subscription bitmap owned by one socket.
pub struct GroupBitmap {
    words: Spinlock<Vec<u32>, SockLockClass>,
}

impl Default for GroupBitmap {
    fn default() -> Self { Self::new() }
}

impl GroupBitmap {
    /// Empty subscription. # C: O(1)
    pub const fn new() -> Self { Self { words: Spinlock::new(Vec::new()) } }

    /// Subscribed to `group` (1-based)? # C: O(1)
    pub fn test(&self, group: u32) -> bool {
        if group == 0 { return false; }
        let (word, bit) = split(group);
        self.words.lock().get(word).is_some_and(|w| w & (1u32 << bit) != 0)
    }

    /// Subscribe to `group` (1-based). # C: O(words)
    pub fn add(&self, group: u32) {
        if group == 0 { return; }
        let (word, bit) = split(group);
        let mut g = self.words.lock();
        if g.len() <= word { g.resize(word + 1, 0); }
        g[word] |= 1u32 << bit;
    }

    /// Unsubscribe from `group` (1-based). # C: O(1)
    pub fn remove(&self, group: u32) {
        if group == 0 { return; }
        let (word, bit) = split(group);
        let mut g = self.words.lock();
        if let Some(w) = g.get_mut(word) { *w &= !(1u32 << bit); }
    }

    /// `bind` nl_groups: replace the low 32 groups, preserving higher ones.
    /// # C: O(words)
    pub fn set_low_mask(&self, mask: u32) {
        let mut g = self.words.lock();
        if g.is_empty() { g.push(0); }
        g[0] = mask;
    }

    /// Low 32 groups as the `sockaddr_nl.nl_groups` word. # C: O(1)
    pub fn low_mask(&self) -> u32 { self.words.lock().first().copied().unwrap_or(0) }

    /// Subscription words covering `ngroups` groups, as
    /// `NETLINK_LIST_MEMBERSHIPS` reports them. # C: O(words)
    pub fn membership_words(&self, ngroups: u32) -> Vec<u32> {
        let need = ngroups.div_ceil(GROUP_BITS_PER_WORD).max(1) as usize;
        let g = self.words.lock();
        let mut out = Vec::with_capacity(need);
        for i in 0..need { out.push(g.get(i).copied().unwrap_or(0)); }
        out
    }

    /// No group subscribed. # C: O(words)
    pub fn is_empty(&self) -> bool { self.words.lock().iter().all(|w| *w == 0) }
}

fn split(group: u32) -> (usize, u32) {
    let bit = group - 1;
    ((bit / GROUP_BITS_PER_WORD) as usize, bit % GROUP_BITS_PER_WORD)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_bit_is_group_minus_one() {
        let b = GroupBitmap::new();
        b.add(1);
        b.add(32);
        assert_eq!(b.low_mask(), (1u32 << 0) | (1u32 << 31));
        assert!(b.test(1) && b.test(32) && !b.test(2));
    }

    #[test]
    fn groups_above_the_first_word_are_reachable() {
        let b = GroupBitmap::new();
        b.add(33);
        b.add(64);
        assert_eq!(b.low_mask(), 0);
        assert!(b.test(33) && b.test(64));
        assert_eq!(b.membership_words(64), alloc::vec![0, (1u32 << 0) | (1u32 << 31)]);
    }

    #[test]
    fn bind_mask_replaces_only_the_low_word() {
        let b = GroupBitmap::new();
        b.add(33);
        b.add(1);
        b.set_low_mask(0xF);
        assert_eq!(b.low_mask(), 0xF);
        assert!(b.test(33));
    }

    #[test]
    fn group_zero_is_never_a_subscription() {
        let b = GroupBitmap::new();
        b.add(0);
        assert!(b.is_empty());
        assert!(!b.test(0));
    }

    #[test]
    fn membership_words_cover_every_group_of_the_protocol() {
        let b = GroupBitmap::new();
        assert_eq!(b.membership_words(0).len(), 1);
        assert_eq!(b.membership_words(32).len(), 1);
        assert_eq!(b.membership_words(33).len(), 2);
        assert_eq!(b.membership_words(RTNLGRP_MAX).len(), 2);
    }
}
