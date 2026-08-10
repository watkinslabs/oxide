// `IORING_SETUP_SINGLE_ISSUER`: WHO owns a ring's submission side, and WHEN
// that ownership is decided.
//
// It is decided at creation, not at first use. `io_uring_setup` records the
// creating task as the ring's submitter, unless the ring was created
// `IORING_SETUP_R_DISABLED` — then `IORING_REGISTER_ENABLE_RINGS` records
// whoever enables it. A ring created by task A and first entered by task B is
// therefore EEXIST: the flag is a guarantee that holds from the moment the
// descriptor exists, not a race the first arrival wins.
//
// Claiming lazily at the first `io_uring_enter` looks equivalent and is not.
// It admits exactly the case the flag exists to exclude, and it does so
// silently, so a program that accidentally submits from two threads gets
// whichever one raced first instead of an error.
//
// A tid of `UNCLAIMED` means no submitter has been recorded. Only an
// `R_DISABLED` ring that has not been enabled is ever in that state; every
// other single-issuer ring is claimed before its descriptor is installed.

use syscall::errno::Errno;

use super::uapi::{IORING_SETUP_R_DISABLED, IORING_SETUP_SINGLE_ISSUER};

/// No submitter recorded. Task ids start at one, so zero cannot collide with a
/// real one.
pub const UNCLAIMED: u32 = 0;

/// Whether `io_uring_setup` records the creating task as the ring's submitter.
/// An `R_DISABLED` ring does not: it is created by one task deliberately so
/// another can be handed it, and the claim moves to the enable. # C: O(1)
pub fn claims_at_setup(flags: u32) -> bool {
    flags & IORING_SETUP_SINGLE_ISSUER != 0 && flags & IORING_SETUP_R_DISABLED == 0
}

/// Whether `IORING_REGISTER_ENABLE_RINGS` records the enabling task as the
/// ring's submitter. It does so for every single-issuer ring, and it overwrites
/// rather than tests — enabling is the point at which a handed-over ring
/// changes hands. # C: O(1)
pub fn claims_at_enable(flags: u32) -> bool {
    flags & IORING_SETUP_SINGLE_ISSUER != 0
}

/// `io_uring_enter`'s admission: on a single-issuer ring only the recorded
/// submitter may submit. An unclaimed ring — an `R_DISABLED` one that nobody
/// enabled — admits nobody, which falls out of the same comparison rather than
/// needing its own rule. # C: O(1)
pub fn admit_submit(flags: u32, submitter: u32, cur: u32) -> Result<(), Errno> {
    if flags & IORING_SETUP_SINGLE_ISSUER == 0 { return Ok(()); }
    if submitter == cur { return Ok(()); }
    Err(Errno::Eexist)
}

/// `io_uring_register`'s admission. It keys off the recorded submitter rather
/// than off the flag: a ring with no submitter recorded — every ring without
/// the flag, and a single-issuer ring still awaiting its enable — is
/// registrable by anyone, which is what lets a task set a disabled ring up
/// before handing it to the task that will run it. # C: O(1)
pub fn admit_register(submitter: u32, cur: u32) -> Result<(), Errno> {
    if submitter == UNCLAIMED || submitter == cur { return Ok(()); }
    Err(Errno::Eexist)
}

#[cfg(test)]
#[path = "issuer/tests.rs"]
mod tests;
