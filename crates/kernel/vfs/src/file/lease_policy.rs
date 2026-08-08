// Lease FLAVOUR + break-state decisions. Pure, ungated, hosted-testable: the
// registry (`lease.rs`) stores one packed word per open file description and
// asks this module every question about it.
//
// One word, one owner: the flavour, the held type and the pending-break state
// all live in `File::lease`. A second field beside it could disagree with it.

use crate::types::VfsError;

/// Lease type values (== record-lock `l_type`): read / write / unlock.
pub const F_RDLCK: i32 = 0;
pub const F_WRLCK: i32 = 1;
pub const F_UNLCK: i32 = 2;

/// Lease flavours, as a BITMASK so a query can name one and a holder can be
/// tested with a single AND. A plain lease (`F_SETLEASE`) and a delegation
/// (`F_SETDELEG`) share one registry, one break path and one state word; they
/// differ only in who may see them and who may break them.
pub const FL_LEASE: i32 = 1;
pub const FL_DELEG: i32 = 2;
/// No lease held.
pub const FL_NONE: i32 = 0;

const TY_MASK: i32 = 0xff;
const FLAVOUR_SHIFT: u32 = 8;
const FLAVOUR_MASK: i32 = 0xff << FLAVOUR_SHIFT;
/// A break wants the holder GONE: the query reports `F_UNLCK` from now on.
pub const FL_UNLOCK_PENDING: i32 = 1 << 16;
/// A break wants the holder DOWNGRADED to a read lease: the query reports
/// `F_RDLCK` from now on.
pub const FL_DOWNGRADE_PENDING: i32 = 1 << 17;

/// The idle word: no flavour, `F_UNLCK`, nothing pending. # C: O(1)
pub const fn unleased() -> i32 { F_UNLCK }

/// Pack a flavour + type into the single lease word. `F_UNLCK` always packs to
/// the idle word, so "no lease" has exactly one representation and cannot be
/// mistaken for a held one whose type happens to read `F_UNLCK`. # C: O(1)
pub fn pack(flavour: i32, ty: i32) -> i32 {
    if ty == F_UNLCK || flavour == FL_NONE { return unleased(); }
    (ty & TY_MASK) | ((flavour << FLAVOUR_SHIFT) & FLAVOUR_MASK)
}

/// Held lease type, ignoring any pending break. # C: O(1)
pub fn ty(word: i32) -> i32 { word & TY_MASK }

/// Held lease flavour (`FL_NONE` when nothing is held). # C: O(1)
pub fn flavour(word: i32) -> i32 { (word & FLAVOUR_MASK) >> FLAVOUR_SHIFT }

/// True while this description holds a lease of any flavour. # C: O(1)
pub fn held(word: i32) -> bool { flavour(word) != FL_NONE && ty(word) != F_UNLCK }

/// True once a break has been signalled and the holder has not yet answered.
/// # C: O(1)
pub fn breaking(word: i32) -> bool {
    word & (FL_UNLOCK_PENDING | FL_DOWNGRADE_PENDING) != 0
}

/// The type a get-lease query reports: while a break is outstanding the answer
/// is what the lease is BECOMING (gone, or downgraded to a read lease), not
/// what it still is — the holder is being told what to do. # C: O(1)
pub fn target_leasetype(word: i32) -> i32 {
    if word & FL_UNLOCK_PENDING != 0 { return F_UNLCK; }
    if word & FL_DOWNGRADE_PENDING != 0 { return F_RDLCK; }
    ty(word)
}

/// The answer a get-lease / get-delegation query gives for `query_flavour`.
/// A description holding a delegation reports NO lease to `F_GETLEASE`, and one
/// holding a plain lease reports NO delegation to `F_GETDELEG`. # C: O(1)
pub fn getlease_report(word: i32, query_flavour: i32) -> i32 {
    if !held(word) { return F_UNLCK; }
    if flavour(word) & query_flavour == 0 { return F_UNLCK; }
    target_leasetype(word)
}

/// Does a holder's lease word conflict with a breaker?
///
/// Two independent rules, in this order:
///   * a DELEGATION break never disturbs a plain LEASE holder — a mutation
///     breaks delegations only, while an open breaks both;
///   * otherwise the record-lock rule: a write lease yields to any breaker, a
///     read lease only to one that wants to write.
/// # C: O(1)
pub fn conflicts(word: i32, breaker_flavour: i32, breaker_writes: bool) -> bool {
    if !held(word) { return false; }
    if breaker_flavour == FL_DELEG && flavour(word) == FL_LEASE { return false; }
    match ty(word) { F_WRLCK => true, F_RDLCK => breaker_writes, _ => false }
}

/// The word a conflicting break installs, or `None` when this holder has
/// already been told (so it is signalled ONCE per break, not once per
/// mutation). A breaker that wants to write demands release; a read breaker
/// demands a downgrade. # C: O(1)
pub fn mark_breaking(word: i32, breaker_writes: bool) -> Option<i32> {
    if breaker_writes {
        if word & FL_UNLOCK_PENDING != 0 { return None; }
        return Some(word | FL_UNLOCK_PENDING);
    }
    if breaking(word) { return None; }
    Some(word | FL_DOWNGRADE_PENDING)
}

/// Which fcntl command asked to set the lease. The two differ in exactly two
/// places: a directory descriptor, and which query can see the result.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LeaseKind { Lease, Deleg }

impl LeaseKind {
    /// Flavour this command records / queries. # C: O(1)
    pub fn flavour(self) -> i32 {
        match self { LeaseKind::Lease => FL_LEASE, LeaseKind::Deleg => FL_DELEG }
    }
}

/// The file types a lease may be taken on, as the caller sees them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LeaseTarget { pub is_dir: bool, pub is_reg: bool }

/// Full set-lease / set-delegation validation ladder, in the order the errors
/// must be reported:
///
/// 1. a set-LEASE on a directory descriptor is `EINVAL` outright — a directory
///    can only be DELEGATED, never leased;
/// 2. `EACCES` unless the caller owns the file or holds `CAP_LEASE`, and this
///    stands even for the release (`F_UNLCK`) form;
/// 3. `EINVAL` on anything that is neither a regular file nor a directory,
///    again including the release form;
/// 4. `EINVAL` for a type outside read / write / unlock, and for a WRITE lease
///    on a directory — a directory delegation is read-only.
/// # C: O(1)
pub fn setlease_check(kind: LeaseKind, t: LeaseTarget, may_lease: bool, ty: i32)
    -> Result<(), VfsError>
{
    if kind == LeaseKind::Lease && t.is_dir { return Err(VfsError::Einval); }
    if !may_lease { return Err(VfsError::Eacces); }
    if !t.is_reg && !t.is_dir { return Err(VfsError::Einval); }
    match ty {
        F_UNLCK => Ok(()),
        F_WRLCK if t.is_dir => Err(VfsError::Einval),
        F_RDLCK | F_WRLCK => Ok(()),
        _ => Err(VfsError::Einval),
    }
}

/// Whether a caller may take a lease at all: it owns the file, or it holds
/// `CAP_LEASE`. # C: O(1)
pub fn may_lease(inode_uid: u32, fsuid: u32, cap_lease: bool) -> bool {
    inode_uid == fsuid || cap_lease
}

/// Can a NEW lease of `ty` be added while `other` (another description's lease
/// word on the same file) exists? An exclusive lease demands sole tenancy, and
/// no new lease may be taken while a break is outstanding — the answer is
/// `EAGAIN`, an invitation to retry, not a permanent refusal. # C: O(1)
pub fn add_lease_conflicts_with_holder(ty: i32, other: i32) -> bool {
    if !held(other) { return false; }
    if ty == F_WRLCK { return true; }
    other & FL_UNLOCK_PENDING != 0
}

/// Does an already-open descriptor forbid this lease? A shared lease requires
/// that nobody has the file open for writing; an exclusive lease requires that
/// the requester is the ONLY writer, which for a read-only requester means no
/// writer at all. `writecount` is the file's live writer count and `self_write`
/// says whether this description is one of them. # C: O(1)
pub fn open_conflicts(ty: i32, writecount: i32, self_write: bool) -> bool {
    match ty {
        F_RDLCK => writecount > 0,
        F_WRLCK => writecount != if self_write { 1 } else { 0 },
        _       => false,
    }
}
