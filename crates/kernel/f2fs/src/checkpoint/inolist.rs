//! The inode numbers a checkpoint epoch has accumulated, by what happened to
//! them.
//!
//! Two of the reasons an `fsync` cannot take the node-chain path are facts
//! about the PARENT directory, and neither is visible from the medium. A
//! directory that lost an entry under a strict mount, and a directory whose
//! attributes were rewritten, both leave a file below them recoverable only
//! through a checkpoint — but the directory's own blocks look, on the medium,
//! exactly like a directory that was merely touched.
//!
//! So the events are RECORDED as they happen, one list per reason, and the
//! decision asks the list. The alternative this replaces was to ask whether
//! the parent's node had been written since the checkpoint, which is true for
//! every ordinary write to a directory: creating a name, moving a timestamp,
//! extending it. Under a strict mount that answered yes almost always, so
//! almost every `fsync` wrote a whole checkpoint — correct, and far more
//! expensive than the contract asks for.
//!
//! A list covers ONE checkpoint epoch. The checkpoint is what makes the
//! parent's blocks durable, so it is also what makes every entry stale, and
//! [`InoLists::release`] is called from the one place a checkpoint is adopted.

use alloc::collections::BTreeSet;

/// Why an inode number was recorded.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum InoKind {
    /// A directory that lost an entry, or gained one by a rename, while the
    /// mount was strict about what an `fsync` promises.
    TransDir = 0,
    /// A directory whose extended attributes were rewritten.
    XattrDir = 1,
}

/// How many lists there are.
pub const INO_KINDS: usize = 2;

/// One list per kind, holding this checkpoint epoch's inode numbers.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InoLists {
    lists: [BTreeSet<u32>; INO_KINDS],
}

impl InoLists {
    /// Nothing recorded yet. # C: O(1)
    pub fn new() -> Self { Self::default() }

    /// Record `ino` on `kind`'s list. Recording one twice is one entry.
    /// # C: O(log n)
    pub fn add(&mut self, kind: InoKind, ino: u32) { self.lists[kind as usize].insert(ino); }

    /// Whether `ino` is on `kind`'s list. # C: O(log n)
    pub fn exists(&self, kind: InoKind, ino: u32) -> bool {
        self.lists[kind as usize].contains(&ino)
    }

    /// How many numbers `kind` holds. # C: O(1)
    pub fn len(&self, kind: InoKind) -> usize { self.lists[kind as usize].len() }

    /// Whether `kind` holds nothing. # C: O(1)
    pub fn is_empty(&self, kind: InoKind) -> bool { self.lists[kind as usize].is_empty() }

    /// Drop every list, which a written checkpoint is what does.
    ///
    /// Not selective, deliberately: a checkpoint makes every directory's
    /// blocks durable at once, so there is no kind whose entries survive one.
    /// # C: O(entries)
    pub fn release(&mut self) { for l in &mut self.lists { l.clear(); } }
}

#[cfg(test)]
#[path = "../tests/inolist.rs"]
mod tests;
