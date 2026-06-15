//! search — <search.h> glibc-ABI (docs/59§6 G8). Binary-tree (tsearch family)
//! and linear (lsearch/lfind) table search. Hash table (hsearch) is a sister
//! file. C ABI only — freestanding.
#[cfg(feature = "freestanding")]
pub mod tree;
#[cfg(feature = "freestanding")]
pub mod lin;
#[cfg(feature = "freestanding")]
pub mod hash;
#[cfg(feature = "freestanding")]
pub mod list;
