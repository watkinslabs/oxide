//! One query name, folded once, then hashed and matched against many entries.
//!
//! A lookup folds the name it is given exactly ONCE and carries the result
//! across every entry it examines. The fold is the expensive part and the
//! entries are many, so folding per entry would make a large directory
//! quadratic in table work for no change in the answer.
//!
//! Three outcomes, and the difference between them is the whole contract:
//!
//! - `.` and `..` are never folded. They hash to zero, as they do in a
//!   directory that does not fold at all, and match byte-exact.
//! - A name the encoding cannot normalize — or whose folded form does not fit
//!   the fixed buffer an entry's name must fit in — is OPAQUE: hashed and
//!   compared as raw bytes. Under strict encoding it is instead refused, since
//!   the volume has declared such names cannot exist on it.
//! - Everything else folds, and it is the FOLDED bytes that are hashed.
//!
//! Matching tries byte equality first. It is the common case, it needs no
//! table, and it is what a case-preserving directory answers with for every
//! caller that spelled the name the way it is stored.
//!
//! An entry whose own stored name is not valid Unicode simply does not match a
//! folded query — it is not an error that fails the lookup, because one
//! unreadable entry must not hide every other entry in the directory.

use syscall::errno::Errno;
use utf8::{casefold_eq, casefold_into, FoldError};

use crate::hash;
use crate::uapi::NAME_LEN;

use super::encoding::Casefold;

/// How a query name resolves.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Fold {
    /// `.` or `..`: hash zero, byte-exact match, never folded.
    DotName,
    /// Folded successfully; the hash is over the folded bytes.
    Folded,
    /// Not normalizable here, and the volume permits it: raw bytes throughout.
    Opaque,
}

/// A prepared query: the caller's name, how it folded, and the folded bytes.
///
/// The folded buffer is the same width an entry name may be, which is also the
/// reference's limit on a folded name — a fold that overflows it is treated as
/// a name the encoding could not produce.
#[derive(Copy, Clone)]
pub struct Query<'a> {
    cf:   &'a Casefold,
    name: &'a [u8],
    kind: Fold,
    buf:  [u8; NAME_LEN],
    len:  usize,
}

/// Whether a name is one of the two never folded. # C: O(1)
fn is_dot_name(name: &[u8]) -> bool { hash::is_dot_or_dotdot(name) }

impl<'a> Query<'a> {
    /// Fold `name` for a lookup in a case-folding directory.
    ///
    /// `EINVAL` only under strict encoding, and only for a name that encoding
    /// cannot represent — a name the volume has promised does not exist on it.
    /// # C: O(len(name))
    pub fn prepare(cf: &'a Casefold, name: &'a [u8]) -> Result<Query<'a>, Errno> {
        let mut q = Query { cf, name, kind: Fold::DotName, buf: [0; NAME_LEN], len: 0 };
        if is_dot_name(name) { return Ok(q); }
        match casefold_into(cf.table(), name, &mut q.buf) {
            Ok(n) => { q.kind = Fold::Folded; q.len = n; Ok(q) }
            // A name that does not normalize and one whose fold does not fit
            // are the same answer: this encoding cannot produce it.
            Err(FoldError::Invalid) | Err(FoldError::NoSpace) => {
                if cf.strict() { return Err(Errno::Einval); }
                q.kind = Fold::Opaque;
                Ok(q)
            }
        }
    }

    /// The name as the caller spelled it. # C: O(1)
    pub fn name(&self) -> &'a [u8] { self.name }

    /// Which of the three outcomes this name took. # C: O(1)
    pub fn kind(&self) -> Fold { self.kind }

    /// The folded bytes, empty unless [`Fold::Folded`]. # C: O(1)
    pub fn folded(&self) -> &[u8] {
        match self.kind { Fold::Folded => &self.buf[..self.len], _ => &[] }
    }

    /// The hash an entry for this name carries, and so the bucket a lookup
    /// searches.
    ///
    /// The folded bytes are hashed when there are any. That is the whole
    /// point: two spellings of one name must reach one bucket.
    /// # C: O(len(name))
    pub fn hash(&self) -> u32 {
        match self.kind {
            Fold::DotName => 0,
            Fold::Folded  => hash::name_hash(self.folded()),
            Fold::Opaque  => hash::name_hash(self.name),
        }
    }

    /// Does the entry named `de_name` answer this query?
    ///
    /// Never fails: an entry whose stored name this encoding cannot read is
    /// reported as not matching, so it hides nothing else in the directory.
    /// # C: O(len(de_name))
    pub fn matches(&self, de_name: &[u8]) -> bool {
        if de_name == self.name { return true; }
        match self.kind {
            // Neither an exempt name nor an opaque one has a folded form to
            // compare against, so byte equality was the whole test.
            Fold::DotName | Fold::Opaque => false,
            Fold::Folded => casefold_eq(self.cf.table(), self.name, de_name).unwrap_or(false),
        }
    }
}
