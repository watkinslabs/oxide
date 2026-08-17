//! The written form of a change to a volume's hot and cold extension lists.
//!
//! One line, and it says three things: which list, whether the name is being
//! added or taken away, and the name. The form is the reference's own because
//! the tools that write it are:
//!
//! ```text
//! [c]iso     add "iso" to the cold list
//! [h]db      add "db" to the hot list
//! [c]!iso    take "iso" out of the cold list
//! ```
//!
//! Pure, so every refusal can be exercised without a volume: an unmarked line
//! names no list and is refused rather than guessed at, because guessing would
//! put a file in the wrong log for the life of the filesystem.

use syscall::errno::Errno;

/// What one written line asks for.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Change<'a> {
    /// The extension, without the marker or the removal sign.
    pub name: &'a str,
    /// The HOT list rather than the cold one.
    pub hot: bool,
    /// Adding it, as against taking it away.
    pub set: bool,
}

/// The marker that names the hot list.
const HOT: &str = "[h]";

/// The marker that names the cold list.
const COLD: &str = "[c]";

/// The sign that turns an addition into a removal.
const UNSET: char = '!';

/// Read one line.
///
/// The name is not bounded here: its length is the superblock array's business
/// and is checked by the editor that writes into it, so the bound cannot come to
/// disagree with the array.
/// # C: O(len)
pub fn parse(line: &str) -> Result<Change<'_>, Errno> {
    let line = line.trim();
    let (hot, rest) = if let Some(r) = line.strip_prefix(HOT) { (true, r) }
                      else if let Some(r) = line.strip_prefix(COLD) { (false, r) }
                      else { return Err(Errno::Einval) };
    let (set, name) = match rest.strip_prefix(UNSET) { Some(n) => (false, n), None => (true, rest) };
    if name.is_empty() { return Err(Errno::Einval); }
    Ok(Change { name, hot, set })
}

#[cfg(test)]
#[path = "../tests/place/extlist.rs"]
mod tests;
