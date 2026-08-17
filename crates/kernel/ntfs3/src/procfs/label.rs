//! `label` — the volume's name, read and written.
//!
//! Writing is what makes this a control: renaming a volume is setting one
//! attribute of one record, and this file is where that operation is reached
//! from. A read-only file here would leave the operation implemented and
//! unreachable.
//!
//! A writer's trailing newlines are not part of the name — `echo NAME > label`
//! is how the file is written, and a volume called "NAME\n" is not what was
//! asked for. Everything else is taken as given, including inner spaces.

use alloc::string::String;
use alloc::sync::Arc;

use vfs::{KResult, VfsError};

use crate::fsattr::{line_str, Attr};
use crate::mount::NtfsFs;

/// The name a writer meant: what they wrote, without the trailing newlines a
/// shell adds. # C: O(len)
pub fn wanted_name(buf: &[u8]) -> &[u8] {
    let mut end = buf.len();
    while end > 0 && buf[end - 1] == b'\n' { end -= 1; }
    &buf[..end]
}

/// The published entry. # C: O(1)
pub fn file(fs: &Arc<NtfsFs>, dev: &str) -> Attr {
    let show_fs = Arc::clone(fs);
    let store_fs = Arc::clone(fs);
    Attr::rw(dev, "label",
             Arc::new(move || Ok(line_str(&show_fs.label()))),
             Arc::new(move |buf: &[u8]| store(&store_fs, buf)))
}

/// Take a write. The count reported is what the writer handed over, including
/// the newline that was not part of the name: a short count would make a
/// standard library retry the remainder as a second name.
/// # C: O(record bytes)
fn store(fs: &NtfsFs, buf: &[u8]) -> KResult<usize> {
    let name = core::str::from_utf8(wanted_name(buf)).map_err(|_| VfsError::Einval)?;
    let name = String::from(name);
    fs.set_label(&name)?;
    Ok(buf.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `echo NAME > label` is how this is written, and the newline the shell
    /// adds is not part of the volume's name.
    #[test]
    fn trailing_newlines_are_not_part_of_the_name() {
        assert_eq!(wanted_name(b"WORK\n"), b"WORK");
        assert_eq!(wanted_name(b"WORK\n\n"), b"WORK");
        assert_eq!(wanted_name(b"WORK"), b"WORK");
    }

    /// Only the trailing ones. A name is allowed spaces, and an empty write
    /// clears the label rather than meaning nothing.
    #[test]
    fn the_rest_of_the_write_is_the_name() {
        assert_eq!(wanted_name(b"MY DISK\n"), b"MY DISK");
        assert_eq!(wanted_name(b"\n"), b"");
        assert_eq!(wanted_name(b""), b"");
    }
}
