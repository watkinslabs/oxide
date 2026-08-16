//! The one call the layer above makes: decode, admit, act.
//!
//! Kept as a single function so the ORDER of the three stages cannot vary by
//! call site. Every earlier attempt at a surface like this grew a second
//! entry point that skipped admission for "the read-only ones", and a
//! read-only command on a filesystem is still a command that reports what the
//! caller may not see.

use sectors::SectorSource;
use syscall::errno::Errno;

use crate::volume::Volume;

use super::exec::{self, Outcome};
use super::perm::{self, Ctx};
use super::req::{self, Extra};
use super::spec;

/// What the layer above must do with the result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Answer {
    /// Write the reply's payload and indirect buffer back, then return its
    /// value.
    Done(super::reply::Reply),
    /// The command is admitted and the volume operation behind it is not
    /// built. Reported as itself so it can never be read as one of the
    /// contract's own refusals.
    NotBuilt(exec::Unbuilt),
}

/// Answer one command against `v`, for the file numbered `ino`.
///
/// `payload` is the fixed argument the copy layer fetched, `extra` the
/// buffers it named by pointer. Nothing here reads caller memory.
/// # C: command-dependent
pub fn handle<S: SectorSource>(v: &mut Volume<S>, ino: u32, cmd: u32, payload: &[u8],
                               extra: &Extra, c: &Ctx) -> Result<Answer, Errno> {
    // A command this filesystem's raw handler does not own must not be
    // answered here at all: answering would shadow whichever stage does own
    // it, and refusing would invent an errno on that stage's behalf.
    if !spec::owns(cmd) { return Err(Errno::Enotty); }
    let facts_v = super::facts::vol_facts(v);
    perm::prologue(&facts_v)?;
    let r = req::decode(cmd, payload, extra, c.cap_sys_admin)?;
    let inode = v.read_inode(ino)?;
    let facts_f = super::facts::file_facts(&inode);
    perm::admit(&r, c, &facts_v, &facts_f)?;
    Ok(match exec::exec(v, ino, c, &r)? {
        Outcome::Reply(reply) => Answer::Done(reply),
        Outcome::NotBuilt(u) => Answer::NotBuilt(u),
    })
}

#[cfg(test)]
#[path = "../tests/ioctl/entry.rs"]
mod tests;
