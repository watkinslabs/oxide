// The relocation walk the trampoline performs, written once in Rust so the
// order it visits entries in is checkable without booting.
//
// This is deliberately NOT expressed in terms of `KImage::relocation_entries`.
// That function is the STAGING side's view of the chain and shares its
// bookkeeping; a check built on it would compare the builder against itself
// and pass however the builder was wrong. This walks raw memory the way the
// assembler does — one `u64` at a time, tagged in its low bits, following an
// indirection to a fresh page — and the test then asserts the two agree.
//
// The order matters and is not arbitrary. `IND_DESTINATION` is tested before
// `IND_INDIRECTION`, `IND_DONE` before `IND_SOURCE`, and the running
// destination advances by one page after each source is copied and at no
// other time. Reorder any of those and an image relocates to the wrong
// addresses — silently, because the machine that would report it is the one
// being replaced.

extern crate alloc;
use alloc::vec::Vec;

use crate::uapi::{IND_DESTINATION, IND_DONE, IND_INDIRECTION, IND_SOURCE, PAGE_MASK, PAGE_SIZE};

/// One move the trampoline makes: `src` page copied over `dst` page.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Copy {
    /// Destination physical page.
    pub dst: u64,
    /// Source physical page.
    pub src: u64,
}

/// Why a walk stopped.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum End {
    /// `IND_DONE` reached — the only healthy outcome.
    Done,
    /// A zero entry: the list was never terminated. The trampoline would run
    /// on into whatever follows, so an image in this state must never reach
    /// the jump.
    Unterminated,
    /// The walk exceeded `limit` entries, i.e. the chain loops.
    TooLong,
}

/// Result of walking one chain.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Walk {
    /// Copies, in the order they happen.
    pub copies: Vec<Copy>,
    /// Why the walk stopped.
    pub end: End,
}

/// Walk the chain rooted at `head`, reading each entry through `read`.
///
/// `read(pa)` returns the `u64` at physical address `pa`; the trampoline's
/// equivalent is a plain load through the identity map. `limit` bounds the
/// walk so a corrupt chain reports rather than hangs.
/// # C: O(N entries)
pub fn walk(head: u64, limit: usize, read: impl Fn(u64) -> u64) -> Walk {
    let mut copies = Vec::new();
    let mut entry = head;
    let mut ptr = 0u64;
    let mut dest = 0u64;
    let mut seen = 0usize;
    loop {
        if seen >= limit { return Walk { copies, end: End::TooLong }; }
        seen += 1;
        if entry == 0 { return Walk { copies, end: End::Unterminated }; }
        let addr = entry & PAGE_MASK;
        if entry & IND_DESTINATION != 0 {
            dest = addr;
        } else if entry & IND_INDIRECTION != 0 {
            ptr = addr;
        } else if entry & IND_DONE != 0 {
            return Walk { copies, end: End::Done };
        } else if entry & IND_SOURCE != 0 {
            copies.push(Copy { dst: dest, src: addr });
            dest += PAGE_SIZE;
        }
        entry = read(ptr);
        ptr += 8;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use alloc::collections::BTreeMap;

    /// A chain laid out by hand, so the walk is checked against entries whose
    /// order the test chose rather than the ones the builder happened to emit.
    struct Mem(BTreeMap<u64, u64>);
    impl Mem {
        fn read(&self) -> impl Fn(u64) -> u64 + '_ { move |pa| *self.0.get(&pa).unwrap_or(&0) }
    }

    /// Lay `entries` out consecutively from `base` and return the head entry
    /// that points at them.
    fn chain(base: u64, entries: &[u64]) -> (u64, Mem) {
        let mut m = BTreeMap::new();
        for (i, e) in entries.iter().enumerate() { m.insert(base + 8 * i as u64, *e); }
        (base | IND_INDIRECTION, Mem(m))
    }

    #[test]
    fn sources_land_on_consecutive_destination_pages() {
        let (head, m) = chain(0x1000, &[
            0x50_0000 | IND_DESTINATION,
            0x9000 | IND_SOURCE,
            0xa000 | IND_SOURCE,
            IND_DONE,
        ]);
        let w = walk(head, 64, m.read());
        assert_eq!(w.end, End::Done);
        assert_eq!(w.copies, [Copy { dst: 0x50_0000, src: 0x9000 },
                              Copy { dst: 0x50_1000, src: 0xa000 }]);
    }

    #[test]
    fn a_new_destination_resets_the_running_address() {
        let (head, m) = chain(0x1000, &[
            0x50_0000 | IND_DESTINATION,
            0x9000 | IND_SOURCE,
            0x70_0000 | IND_DESTINATION,
            0xa000 | IND_SOURCE,
            IND_DONE,
        ]);
        assert_eq!(walk(head, 64, m.read()).copies,
                   [Copy { dst: 0x50_0000, src: 0x9000 },
                    Copy { dst: 0x70_0000, src: 0xa000 }]);
    }

    #[test]
    fn an_indirection_continues_the_walk_on_another_page() {
        let mut m = BTreeMap::new();
        m.insert(0x1000, 0x50_0000 | IND_DESTINATION);
        m.insert(0x1008, 0x9000 | IND_SOURCE);
        m.insert(0x1010, 0x2000 | IND_INDIRECTION);
        m.insert(0x2000, 0xa000 | IND_SOURCE);
        m.insert(0x2008, IND_DONE);
        let mem = Mem(m);
        let w = walk(0x1000 | IND_INDIRECTION, 64, mem.read());
        assert_eq!(w.end, End::Done);
        assert_eq!(w.copies, [Copy { dst: 0x50_0000, src: 0x9000 },
                              Copy { dst: 0x50_1000, src: 0xa000 }]);
    }

    #[test]
    fn a_missing_terminator_is_reported_rather_than_walked_past() {
        let (head, m) = chain(0x1000, &[0x50_0000 | IND_DESTINATION, 0x9000 | IND_SOURCE]);
        assert_eq!(walk(head, 64, m.read()).end, End::Unterminated);
    }

    #[test]
    fn a_chain_that_loops_terminates() {
        let mut m = BTreeMap::new();
        m.insert(0x1000, 0x1000 | IND_INDIRECTION);
        assert_eq!(walk(0x1000 | IND_INDIRECTION, 8, Mem(m).read()).end, End::TooLong);
    }

    #[test]
    fn done_outranks_source_on_one_entry() {
        // A terminator that also carried the source bit must stop the walk,
        // not copy a page from address zero and keep going.
        let (head, m) = chain(0x1000, &[IND_DONE | IND_SOURCE]);
        let w = walk(head, 64, m.read());
        assert_eq!(w.end, End::Done);
        assert!(w.copies.is_empty());
    }
}
