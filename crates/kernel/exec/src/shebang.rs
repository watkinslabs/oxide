//! The `#!` interpreter line.
//!
//! An executable whose first two bytes are `#!` names the program that should
//! run it, optionally with one argument, on the rest of that first line. The
//! parse has more rules than it looks: only the FIRST line is considered, only
//! ONE argument is recognised however many words follow, and a line long enough
//! to have been truncated by the read buffer is refused rather than run — a
//! truncated interpreter path names a different program than the file does.
//!
//! Pure and ungated on purpose. The boot path that consumes it can only run in
//! a kernel; this decision is tested without one.

use crate::uapi::BINPRM_BUF_SIZE;

/// A parsed interpreter line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Shebang<'a> {
    /// The program to run.
    pub interp: &'a [u8],
    /// Its single optional argument — everything after the interpreter, with
    /// surrounding blanks removed, kept whole however many words it holds.
    pub arg: Option<&'a [u8]>,
}

fn spacetab(b: u8) -> bool { b == b' ' || b == b'\t' }

/// Parse the interpreter line of `blob`.
///
/// `None` when the file does not begin `#!`, when the line names no
/// interpreter, or when the first line is longer than the buffer the parse
/// looks at and so may be truncated.
/// # C: O(BINPRM_BUF_SIZE)
pub fn parse(blob: &[u8]) -> Option<Shebang<'_>> {
    let buf = &blob[..core::cmp::min(blob.len(), BINPRM_BUF_SIZE)];
    if buf.len() < 2 || buf[0] != b'#' || buf[1] != b'!' { return None; }
    let body = &buf[2..];
    // The line ends at the first newline. Without one, the line is only
    // trustworthy if the whole buffer was the whole file — otherwise the
    // interpreter path may be cut short, and running a prefix of a path is
    // worse than refusing.
    let mut end = match body.iter().position(|b| *b == b'\n') {
        Some(n) => n,
        None if blob.len() <= BINPRM_BUF_SIZE => body.len(),
        None => return None,
    };
    while end > 0 && spacetab(body[end - 1]) { end -= 1; }
    let line = &body[..end];
    let start = line.iter().position(|b| !spacetab(*b))?;
    let line = &line[start..];
    if line.is_empty() { return None; }
    match line.iter().position(|b| spacetab(*b)) {
        None => Some(Shebang { interp: line, arg: None }),
        Some(sep) => {
            let rest = &line[sep..];
            let at = rest.iter().position(|b| !spacetab(*b));
            Some(Shebang { interp: &line[..sep], arg: at.map(|a| &rest[a..]) })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_interpreter_line_names_it_and_no_argument() {
        let s = parse(b"#!/bin/bash\necho hi\n").unwrap();
        assert_eq!(s.interp, b"/bin/bash");
        assert_eq!(s.arg, None);
    }

    #[test]
    fn one_argument_is_recognised() {
        let s = parse(b"#!/bin/sh -e\n").unwrap();
        assert_eq!(s.interp, b"/bin/sh");
        assert_eq!(s.arg, Some(&b"-e"[..]));
    }

    /// Several words after the interpreter are ONE argument, not several —
    /// which is why `#!/usr/bin/env python3 -u` passes `python3 -u` as a single
    /// string and surprises people.
    #[test]
    fn everything_after_the_interpreter_is_a_single_argument() {
        let s = parse(b"#!/usr/bin/env python3 -u\n").unwrap();
        assert_eq!(s.interp, b"/usr/bin/env");
        assert_eq!(s.arg, Some(&b"python3 -u"[..]));
    }

    #[test]
    fn leading_and_trailing_blanks_are_removed() {
        let s = parse(b"#!  \t /bin/sh \t  \n").unwrap();
        assert_eq!(s.interp, b"/bin/sh");
        assert_eq!(s.arg, None);
    }

    #[test]
    fn a_file_that_does_not_begin_with_the_marker_is_not_a_script() {
        assert!(parse(b"\x7fELF\x02\x01\x01").is_none());
        assert!(parse(b"#x/bin/sh\n").is_none());
        assert!(parse(b"#").is_none());
        assert!(parse(b"").is_none());
    }

    #[test]
    fn a_line_naming_no_interpreter_is_refused() {
        assert!(parse(b"#!\n").is_none());
        assert!(parse(b"#!   \t \nls\n").is_none());
    }

    /// A first line longer than the parse buffer may have been cut short, and
    /// a truncated path names a different program than the file does.
    #[test]
    fn a_first_line_that_may_be_truncated_is_refused() {
        let mut blob = alloc::vec::Vec::from(&b"#!/"[..]);
        blob.resize(BINPRM_BUF_SIZE + 64, b'a');
        assert!(parse(&blob).is_none());
    }

    /// The same length is fine once a newline proves the line is whole.
    #[test]
    fn a_long_line_terminated_inside_the_buffer_is_accepted() {
        let mut blob = alloc::vec::Vec::from(&b"#!/"[..]);
        blob.resize(BINPRM_BUF_SIZE - 8, b'a');
        blob.push(b'\n');
        assert_eq!(parse(&blob).unwrap().interp.len(), BINPRM_BUF_SIZE - 8 - 2);
    }

    /// A short file with no newline at all is whole, so it parses.
    #[test]
    fn a_short_file_with_no_newline_is_whole() {
        assert_eq!(parse(b"#!/bin/sh").unwrap().interp, b"/bin/sh");
    }
}
