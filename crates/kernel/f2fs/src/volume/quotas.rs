//! Charging allocations to the identities that own them.
//!
//! The decode, the tree walk and the limit decision are pure and live under
//! `quota`. This is the half that makes them mean something: every block a
//! file gains and every inode a directory gains is charged here, and a mount
//! that enforces limits refuses the allocation rather than recording an
//! overdraft after the fact.
//!
//! The split follows WHEN each half runs. Records are brought in at an
//! operation's entry and never below it; the charge then operates on what is
//! already held. Reading a quota file from inside a charge put a whole file read
//! — index walk, block fetch, attestation, page lock — underneath every node
//! write in the filesystem, which is not what the reference does and not what
//! the stack can hold.
//!
//! A quota file's OWN blocks are never charged. Charging the growth of the file
//! that records an identity's usage to that identity is a loop that does not
//! terminate.
//!
//! Module manifest:
//! - `kinds`:   the identity an allocation is charged to, and the kind numbering.
//! - `acquire`: bringing records in at an operation's entry, and the files they
//!              come from. The only quota-file READ on an allocation path.
//! - `charge`:  the limit decision and the counts, over records already held.
//! - `transfer`: moving one inode's usage when its identity changes.
//! - `records`: reading and setting limits, for a caller that is not allocating.
//! - `flush`:   writing changed records back, at checkpoint.

#[path = "quotas/kinds.rs"] mod kinds;
#[path = "quotas/acquire.rs"] mod acquire;
#[path = "quotas/charge.rs"] mod charge;
#[path = "quotas/transfer.rs"] mod transfer;
#[path = "quotas/records.rs"] mod records;
#[path = "quotas/flush.rs"] mod flush;

pub use kinds::{Owners, DEFAULT_PROJID, GRPQUOTA, PRJQUOTA, USRQUOTA};

#[cfg(test)]
#[path = "../tests/quotawire.rs"]
mod tests;
