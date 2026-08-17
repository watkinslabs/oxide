//! The mount's master keys, and an encrypted inode's key when it has one.
//!
//! A key is not on the volume. It is handed to the mount at runtime and lives
//! only in memory, so the same inode is readable or merely listable depending
//! on whether the key its context names has been added. Both states are
//! normal, and neither is an error: a locked directory still lists, and a
//! locked file still unlinks.
//!
//! The context, by contrast, IS on the volume — an attribute on every
//! encrypted inode, reached by INDEX rather than by a name a caller could
//! pass, the same way the verity location is. An inode flagged encrypted with
//! no context is damaged rather than merely locked, because nothing else
//! records which key and which modes its bytes were written under.
//!
//! Module manifest — split along WHEN each half runs, which is the distinction
//! the whole file is about:
//!
//! | child | owns |
//! |---|---|
//! | `keys` | the mount's master-key table, and the facts a policy is set up against |
//! | `setup` | resolving an inode's key ONCE, at the operation that enters the file, and handing the held record to everything below |
//! | `contents` | putting the cipher on and taking it off one block, given a record the caller already holds |

pub mod keys;
pub mod setup;
pub mod contents;
