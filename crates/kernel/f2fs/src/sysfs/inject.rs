//! `/sys/fs/f2fs/<dev>/` — the failures this mount injects on purpose.
//!
//! Three controls over one record, and each write carries only its own field:
//! setting the rate must not reset which sites are armed, and arming a site must
//! not reset the rate. That is why `fault::Which` exists and why each store here
//! names exactly one bit of it.
//!
//! A rejected value changes NOTHING, so a caller that writes a knob and reads it
//! back sees either the new value or the old one — never a half-applied pair.
//! The bounds are owned by the `fault` module, which is what the injection sites
//! consult, so the published surface cannot come to accept a value no site would
//! act on.

use alloc::sync::Arc;
use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::fault::Which;
use crate::fsattr::Attr;
use crate::mount::F2fs;

use super::volume::{num_rw, Vol};

/// The three injection controls. # C: O(1)
pub(crate) fn attrs(fs: &Arc<F2fs>, dev: &str) -> Vec<Attr> {
    alloc::vec![
        num_rw(fs, dev, "inject_rate", |v| u64::from(v.fault_info().rate()), set_rate),
        num_rw(fs, dev, "inject_type", |v| u64::from(v.fault_info().types()), set_type),
        num_rw(fs, dev, "inject_lock_timeout",
               |v| u64::from(v.fault_info().timeout() as u32), set_lock_timeout),
    ]
}

/// One consultation in every `rate` fails; zero turns injection off.
/// # C: O(1)
fn set_rate(v: &mut Vol, n: u64) -> Result<(), Errno> {
    let rate = u32::try_from(n).map_err(|_| Errno::Einval)?;
    v.set_fault(rate, 0, Which::RATE)
}

/// Which sites are armed, as a bit per site.
///
/// A word naming a site this build has no injection point for is refused rather
/// than stored, because a stored bit nothing reads would report an armed site
/// that can never fire.
/// # C: O(1)
fn set_type(v: &mut Vol, n: u64) -> Result<(), Errno> {
    let types = u32::try_from(n).map_err(|_| Errno::Einval)?;
    v.set_fault(0, types, Which::TYPE)
}

/// How a lock asked to time out does so, as one of the named kinds.
///
/// An index past the last kind is refused: the value selects behaviour rather
/// than scaling it, so an unrecognised one has no meaning to fall back on.
/// # C: O(1)
fn set_lock_timeout(v: &mut Vol, n: u64) -> Result<(), Errno> {
    let index = u32::try_from(n).map_err(|_| Errno::Einval)?;
    v.set_fault(0, index, Which::TIMEOUT)
}

#[cfg(test)]
#[path = "../tests/sysfs/inject.rs"]
mod tests;
