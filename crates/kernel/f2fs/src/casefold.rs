//! Case-insensitive name resolution.
//!
//! A case-folding directory does not store the name a lookup asks for. It
//! stores whatever bytes the creator supplied, and resolves a query by folding
//! BOTH sides through a Unicode table. Two consequences drive everything here,
//! and each one, got wrong, makes a name that exists unfindable with no error
//! anywhere:
//!
//! - **The bucket is chosen by the hash of the FOLDED name, not of the stored
//!   bytes.** `README` and `readme` must land in one bucket or the second
//!   spelling searches a bucket the entry is not in. The hash function itself
//!   is unchanged — only what is fed to it.
//! - **Two names are exempt.** `.` and `..` hash to zero and are compared
//!   byte-exact, never folded. So is any name the encoding cannot normalize:
//!   it degrades to an opaque byte sequence, hashed and compared raw, unless
//!   the volume asked for STRICT encoding — in which case such a name is an
//!   error rather than a name.
//!
//! The third trap is historical. A volume written before its encoding changed
//! holds entries hashed under the old rules, so the bucket a fold picks today
//! can be the wrong one for an entry written yesterday. A hash-directed lookup
//! that finds nothing therefore may have to rescan the whole directory with
//! the hash ignored. Whether it does is a mount decision, not a guess.
//!
//! Nothing here touches a medium: every entry point is a pure function of
//! bytes, so the whole contract is testable without an image.
//!
//! Module manifest:
//! - `encoding`: the superblock's encoding number and flags, and the table.
//! - `name`:     folding one query, and the hash and match predicate it gives.
//! - `lookup`:   which passes a lookup makes, from the mount's lookup mode.

mod encoding;
mod name;
mod lookup;

pub use encoding::{
    encoding_for, Casefold, EncodingInfo, EncodingRefusal,
    ENC_NO_COMPAT_FALLBACK_FL, ENC_STRICT_MODE_FL, F2FS_ENC_UTF8_12_1,
};
pub use name::{Fold, Query};
pub use lookup::{
    fallback_to_linear, plan, plan_for, LookupMode, Pass, Plan, DEFAULT_LOOKUP_MODE,
};

#[cfg(test)]
#[path = "tests/casefold.rs"]
mod tests;
