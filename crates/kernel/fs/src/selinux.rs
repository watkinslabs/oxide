// Kernel glue between the label engine and the objects it labels.
//
// The engine below decides over values and the VFS above owns the objects, so
// something has to read one and call the other. That is all this module does:
// it reads the inode's mode, its filesystem type and its written label, asks,
// and stores the answer back on the inode. No decision is taken here, and no
// label is stored anywhere but on the object that carries it.
//
// Module manifest:
//   label — resolve and cache an inode's label from the object's own state
//   perm  — the inode permission check the VFS calls
//   xattr — the `security.*` attribute gate the xattr rules call

pub mod label;
pub mod perm;
pub mod xattr;

pub use label::{inode_sid, superblock_security};
pub use perm::{inode_permission, install};
pub use xattr::xattr_gate;
