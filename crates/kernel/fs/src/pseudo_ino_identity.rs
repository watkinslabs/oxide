//! Identity and number-space decisions for this crate's anon-inode families.
//!
//! Two separate contracts, and the tests keep them separate on purpose:
//!
//! * IDENTITY — "is this fd one of mine?" — is answered by the backend state
//!   the inode owns, exactly as Linux compares `f_op` against the one vtable
//!   the subsystem installs. An inode NUMBER never answers it: a foreign inode
//!   carrying a family's exact number must be refused, or the handler that
//!   number admitted it to reads an unrelated `i_private` as its own state.
//! * NUMBERING — a family's numbers stay inside the range `vfs::pseudo_ino`
//!   reserves for it, however many objects are created, so one owner's counter
//!   cannot silently become another owner's number.
//!
//! Ungated on purpose (`#[cfg(test)]` inside a `cfg(target_os =
//! "oxide-kernel")` module compiles out and reports nothing).

#[cfg(test)]
#[path = "pseudo_ino_identity/tests.rs"]
mod tests;
