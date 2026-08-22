// What an operation on a `security.*` attribute is allowed to demand.
//
// The label attribute is not an ordinary attribute: reading it reads the
// object's metadata, and writing it MOVES the object between labels. Treating
// the whole namespace as one thing — the state this replaces, where every
// `security.*` operation was permitted outright — leaves the label writable by
// anyone the discretionary rules let near the file.

extern crate alloc;
use alloc::vec::Vec;

use crate::label::XATTR_NAME_SELINUX;

/// Permission a read of an object's metadata asks for.
pub const PERM_GETATTR: &str = "getattr";

/// Permission a non-label attribute mutation asks for.
pub const PERM_SETATTR: &str = "setattr";

/// `XATTR_SELINUX_SUFFIX` — what `XATTR_NAME_SELINUX` is left as once the
/// `security.` prefix the VFS strips is gone.
pub const SELINUX_SUFFIX: &str = "selinux";

/// Which kind of attribute operation is being attempted.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum XattrOp {
    /// Read the attribute's value.
    Get,
    /// Write a new value.
    Set,
    /// Delete the attribute.
    Remove,
    /// Enumerate every attribute name.
    List,
}

/// What the operation costs.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum XattrGate {
    /// One permission on the object's own class.
    Perm(&'static str),
    /// The full relabel ladder against the value being written.
    Relabel,
    /// Refused outright, whatever the caller holds.
    Refuse,
}

/// Gate one attribute operation. # C: O(1)
///
/// Deleting the label is refused rather than priced: a label may be CHANGED,
/// but every object must have one. An object whose label can be removed is one
/// a domain can drop back to the mount default, and a filesystem holding such
/// objects no longer describes what it holds.
pub fn selinux_xattr_gate(name: &str, op: XattrOp) -> XattrGate {
    match op {
        XattrOp::Get => XattrGate::Perm(PERM_GETATTR),
        XattrOp::List => XattrGate::Perm(PERM_GETATTR),
        XattrOp::Set if name == XATTR_NAME_SELINUX => XattrGate::Relabel,
        XattrOp::Remove if name == XATTR_NAME_SELINUX => XattrGate::Refuse,
        XattrOp::Set | XattrOp::Remove => XattrGate::Perm(PERM_SETATTR),
    }
}

/// `selinux_inode_getsecurity`'s name test. This module answers for exactly one
/// suffix; every other `security.*` name is `EOPNOTSUPP`, which is the signal
/// that sends the read on to the filesystem's own attribute store.
/// # C: O(1)
pub fn answers_getsecurity(suffix: &str) -> bool { suffix == SELINUX_SUFFIX }

/// The attribute VALUE a label read reports.
///
/// The length is `strlen + 1`: the terminating NUL is part of the attribute, so
/// a reader that treats the result as a C string — which every consumer of this
/// attribute does — finds its terminator inside the bytes it was given. Handing
/// back one byte fewer leaves that reader running off the end of its buffer.
/// # C: O(len)
pub fn getsecurity_value(context: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(context.len() + 1);
    out.extend_from_slice(context.as_bytes());
    out.push(0);
    out
}
