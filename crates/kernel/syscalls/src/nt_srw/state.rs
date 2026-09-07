//! The slim reader/writer lock is one 32-bit word holding two counters. The
//! low half counts exclusive interest: bit 0 records that the lock is held for
//! writing, and the bits above it count waiting writers, so a waiter arrives
//! by adding two. The high half counts owners, one per reader or the single
//! writer. Owners must not be the low half: a blocked writer waits on the
//! owner half alone while a blocked reader waits on the whole word, and only
//! that split lets a release wake writers without also waking readers.

/// Bit recording that the lock is held for writing.
pub const EXCLUSIVE_HELD: u32 = 0x0000_0001;
/// One waiting writer, in the exclusive half.
pub const EXCLUSIVE_WAITER: u32 = 0x0000_0002;
/// Mask of the exclusive half.
pub const EXCLUSIVE_MASK: u32 = 0x0000_ffff;
/// Distance from the word base to the owner half.
pub const OWNERS_SHIFT: u32 = 16;
/// One owner, in the owner half.
pub const ONE_OWNER: u32 = 1 << OWNERS_SHIFT;
/// Byte offset of the owner half inside the lock word.
pub const OWNERS_BYTE_OFFSET: u64 = 2;
/// Flag naming a shared, rather than exclusive, condition-variable lock mode.
pub const CONDITION_VARIABLE_LOCKMODE_SHARED: u32 = 0x0001;

/// Owners recorded in one lock word. # C: O(1)
pub const fn owners(word: u32) -> u32 { word >> OWNERS_SHIFT }
/// Exclusive interest recorded in one lock word: the held bit and the waiters. # C: O(1)
pub const fn exclusive(word: u32) -> u32 { word & EXCLUSIVE_MASK }

/// Announce a waiting writer before its first attempt, as an unconditional add
/// of one waiter to the exclusive half.
/// # C: O(1)
pub const fn announce_exclusive_waiter(word: u32) -> u32 {
    (exclusive(word).wrapping_add(EXCLUSIVE_WAITER) & EXCLUSIVE_MASK) | (owners(word) << OWNERS_SHIFT)
}

/// One attempt by an announced writer. `Some` is the word to install; `None`
/// means an owner holds the lock and the writer must wait. Taking it both
/// retires this writer's announcement and sets the held bit.
/// # C: O(1)
pub const fn take_announced_exclusive(word: u32) -> Option<u32> {
    if owners(word) != 0 { return None; }
    let waiters = exclusive(word).wrapping_sub(EXCLUSIVE_WAITER) & EXCLUSIVE_MASK;
    Some(ONE_OWNER | waiters | EXCLUSIVE_HELD)
}

/// One attempt by a writer that never announced itself, which is what the
/// non-blocking acquire is. `None` means the attempt fails rather than waits.
/// # C: O(1)
pub const fn try_take_exclusive(word: u32) -> Option<u32> {
    if owners(word) != 0 { return None; }
    Some(ONE_OWNER | exclusive(word) | EXCLUSIVE_HELD)
}

/// One attempt by a reader. `None` means a writer holds or wants the lock, so
/// the reader waits rather than overtaking it.
/// # C: O(1)
pub const fn take_shared(word: u32) -> Option<u32> {
    if exclusive(word) != 0 { return None; }
    Some(word.wrapping_add(ONE_OWNER))
}

/// Drop the exclusive claim: no owners remain and the held bit clears, while
/// the waiter count is untouched.
/// # C: O(1)
pub const fn drop_exclusive(word: u32) -> u32 { exclusive(word) & !EXCLUSIVE_HELD }

/// Drop one shared claim.
/// # C: O(1)
pub const fn drop_shared(word: u32) -> u32 { word.wrapping_sub(ONE_OWNER) }

/// Which sleepers a release must disturb. A word still carrying exclusive
/// interest wakes one writer through the owner half; otherwise every reader
/// blocked on the whole word is released.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Wake { OneWriter, AllOnWord, None }

/// Wake decision after an exclusive release, given the installed word.
/// # C: O(1)
pub const fn wake_after_exclusive_release(installed: u32) -> Wake {
    if exclusive(installed) != 0 { Wake::OneWriter } else { Wake::AllOnWord }
}

/// Wake decision after a shared release: only the last reader out disturbs a
/// writer, and a lock still held by readers wakes nobody.
/// # C: O(1)
pub const fn wake_after_shared_release(installed: u32) -> Wake {
    if owners(installed) == 0 { Wake::OneWriter } else { Wake::None }
}
