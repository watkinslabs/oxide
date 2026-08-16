//! Who may open, commit and abandon a span, and what refuses one.
//!
//! Pure decisions over stated facts. The facts that come from the file
//! DESCRIPTION rather than the inode — whether the handle was opened for
//! writing, whether the caller owns the file, whether the handle bypasses the
//! page cache — are carried in separately, because this crate never sees a
//! file description and a caller that has one must not have to guess the
//! order the refusals are asked in.

use syscall::errno::Errno;

/// What the caller's handle allows.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct AtomicGate {
    /// The handle was opened for writing.
    pub writable_handle: bool,
    /// The caller owns the file, or may act as though it did.
    pub owner_or_capable: bool,
    /// The stored type is a regular file.
    pub is_reg: bool,
    /// The handle bypasses the page cache.
    pub o_direct: bool,
    /// The mount refuses writes.
    pub ro_mount: bool,
}

/// What the inode and the volume say.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct AtomicFacts {
    /// The file is pinned, so its blocks may not move — and a commit is
    /// nothing but a move.
    pub pinned: bool,
    /// The file is compressed and the compression cannot be turned off,
    /// because it already holds compressed blocks.
    pub compressed_undisableable: bool,
    /// A span is already open on this file.
    pub already_atomic: bool,
}

/// What a START resolves to.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum StartAction {
    /// A span is already open; the call is a no-op.
    AlreadyOpen,
    /// Open one.
    Open,
}

/// The handle-level ladder every one of the three shares.
///
/// `EBADF` before `EACCES` before the mount: a handle that cannot write is
/// refused for being the wrong handle, not for belonging to the wrong caller.
/// # C: O(1)
pub fn handle_gate(g: &AtomicGate) -> Result<(), Errno> {
    if !g.writable_handle { return Err(Errno::Ebadf); }
    if !g.owner_or_capable { return Err(Errno::Eacces); }
    if g.ro_mount { return Err(Errno::Erofs); }
    Ok(())
}

/// Whether a span may be opened.
///
/// The direct-I/O refusal is not incidental: a span's writes are held apart
/// from the file until the commit, and a handle that writes straight through
/// to the medium has nowhere to hold them.
/// # C: O(1)
pub fn start_atomic_write(g: &AtomicGate, f: &AtomicFacts) -> Result<StartAction, Errno> {
    if !g.writable_handle { return Err(Errno::Ebadf); }
    if !g.owner_or_capable { return Err(Errno::Eacces); }
    if !g.is_reg { return Err(Errno::Einval); }
    if g.o_direct { return Err(Errno::Einval); }
    if g.ro_mount { return Err(Errno::Erofs); }
    if f.compressed_undisableable || f.pinned { return Err(Errno::Einval); }
    if f.already_atomic { return Ok(StartAction::AlreadyOpen); }
    Ok(StartAction::Open)
}

/// Whether a span may be committed. # C: O(1)
pub fn commit_atomic_write(g: &AtomicGate) -> Result<(), Errno> { handle_gate(g) }

/// Whether a span may be abandoned.
///
/// Abandoning a file with no span open succeeds: the state the caller asked
/// for is the state it is already in, and reporting an error would make a
/// cleanup path have to know whether its own earlier call got as far as
/// opening one.
/// # C: O(1)
pub fn abort_atomic_write(g: &AtomicGate) -> Result<(), Errno> { handle_gate(g) }

/// Whether a write through a handle may proceed.
///
/// A direct write and an open span are incompatible for the same reason a
/// span cannot be opened on a direct handle, and the refusal has to be here
/// too: the handle may have been opened before the span was.
/// # C: O(1)
pub fn write_iter(atomic: bool, dio: bool) -> Result<(), Errno> {
    if atomic && dio { return Err(Errno::Eopnotsupp); }
    Ok(())
}

/// Whether verity may be turned on.
///
/// Sealing a file behind a hash tree while a span is open would attest to
/// bytes the commit is about to replace.
/// # C: O(1)
pub fn enable_verity(atomic: bool) -> Result<(), Errno> {
    if atomic { return Err(Errno::Eopnotsupp); }
    Ok(())
}

/// Whether a range may be shared or moved between two files.
///
/// Compressed and pinned files are refused because neither's blocks mean what
/// the operation assumes; an open span is refused separately and with a
/// different errno, which is the reference's own distinction between "this
/// file's blocks are not that shape" and "this file is mid-transaction".
/// # C: O(1)
pub fn clone_range(compressed_or_pinned: bool, atomic: bool) -> Result<(), Errno> {
    if compressed_or_pinned { return Err(Errno::Eopnotsupp); }
    if atomic { return Err(Errno::Einval); }
    Ok(())
}
