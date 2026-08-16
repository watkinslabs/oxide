// Per-request operation flags — the modifiers that ride alongside `BlockOp`.
//
// `BlockOp` says WHAT to do with a range of blocks. These say what is true
// ABOUT the request beyond that: who it is for, and how urgent it is relative
// to the ordinary stream of file data. They are deliberately a bit word rather
// than a field per modifier, because a submitter that wants to say two things
// about one request says both.
//
// Every flag here is a HINT. Nothing in this word may change what lands on the
// medium, only the order it lands in: a device that ignores the whole word
// still stores exactly the same bytes. A modifier that carries a DURABILITY
// promise (forced unit access, pre-flush) is not in this word, because
// honouring one needs a flush sequencer this layer does not have, and a
// promise nothing keeps is worse than one nobody made.
//
// Ungated on purpose: the flags and the predicate over them are the contract,
// and they are hosted-tested here rather than in a driver.

/// What a submitter says about a request, beyond the operation itself.
///
/// Constructed from the named constants and combined with `|`. An empty word
/// is an ordinary request, which is what every submitter that does not care
/// produces.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct RequestFlags(u32);

/// This request carries filesystem METADATA rather than file contents.
///
/// Metadata gates the data that depends on it — a directory block, a node
/// table entry, or a summary is read before the blocks it names can be reached
/// — so a queue that has to choose starts it ahead of an ordinary data
/// request of the same priority class.
pub const META: RequestFlags = RequestFlags(1 << 0);

/// Boost this request ahead of others in its priority class.
///
/// The submitter has decided this particular request matters more than the
/// rest of its stream, without claiming a different priority CLASS: a task's
/// I/O priority is a property of the task, and a per-request hint must not be
/// able to rewrite it. A queue honours this only when choosing between
/// requests it would otherwise have started in arrival order.
pub const PRIO: RequestFlags = RequestFlags(1 << 1);

/// The flags that mark a request as more urgent than plain file data.
///
/// One predicate rather than two tests at every queue, so a flag added to this
/// set takes effect everywhere at once instead of in whichever queues someone
/// remembered.
const HIPRIO: RequestFlags = RequestFlags(META.0 | PRIO.0);

impl RequestFlags {
    /// No modifiers — an ordinary request. # C: O(1)
    pub const NONE: RequestFlags = RequestFlags(0);

    /// Whether every flag in `other` is set here. # C: O(1)
    pub const fn contains(self, other: RequestFlags) -> bool { self.0 & other.0 == other.0 }

    /// Whether this request should be started ahead of an ordinary one of the
    /// same priority class. # C: O(1)
    pub const fn is_hiprio(self) -> bool { self.0 & HIPRIO.0 != 0 }

    /// The same word with `other` also set. # C: O(1)
    pub const fn with(self, other: RequestFlags) -> RequestFlags { RequestFlags(self.0 | other.0) }
}

impl core::ops::BitOr for RequestFlags {
    type Output = RequestFlags;
    /// # C: O(1)
    fn bitor(self, other: RequestFlags) -> RequestFlags { self.with(other) }
}

impl core::ops::BitOrAssign for RequestFlags {
    /// # C: O(1)
    fn bitor_assign(&mut self, other: RequestFlags) { self.0 |= other.0; }
}

#[cfg(test)]
mod tests;
