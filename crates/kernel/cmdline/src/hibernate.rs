//! Ordered hibernation boot-option decisions.

use crate::token::{split_token, tokens};

/// Boot-time hibernation request. The target borrows the canonical command
/// line; its owner decides when to copy or resolve it.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Options<'a> {
    pub resume: Option<&'a [u8]>,
    pub resume_offset: u64,
    pub compressor: Option<&'a [u8]>,
    pub nocompress: bool,
    pub noresume: bool,
    pub nohibernate: bool,
}

/// Parse the hibernation options in command-line order. Once either disabling
/// flag is seen, later resume values are ignored. # C: O(line length)
pub fn options(line: &[u8]) -> Options<'_> {
    let mut out = Options::default();
    for token in tokens(line) {
        let (key, value) = split_token(token);
        match (key, value) {
            (b"noresume", None) => out.noresume = true,
            (b"nohibernate", None) => { out.noresume = true; out.nohibernate = true; }
            (b"hibernate", Some(value)) if value.starts_with(b"noresume") => {
                out.noresume = true;
            }
            (b"resume", Some(value)) if !out.noresume => out.resume = Some(value),
            (b"resume_offset", Some(value)) if !out.noresume => {
                if let Some(offset) = decimal_prefix(value) { out.resume_offset = offset; }
            }
            (b"hibernate", Some(value)) if value.starts_with(b"nocompress") => {
                out.nocompress = true;
            }
            (b"hibernate", Some(value)) if value.starts_with(b"no") => {
                out.noresume = true;
                out.nohibernate = true;
            }
            (b"hibernate.compressor", Some(value)) => out.compressor = Some(value),
            _ => {}
        }
    }
    out
}

fn decimal_prefix(value: &[u8]) -> Option<u64> {
    let mut out = 0u64;
    let mut digits = 0usize;
    for byte in value {
        if !byte.is_ascii_digit() { break; }
        out = out.checked_mul(10)?.checked_add((byte - b'0') as u64)?;
        digits += 1;
    }
    (digits != 0).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn last_values_win_until_resume_is_disabled() {
        assert_eq!(options(b"resume=/dev/a resume_offset=7 resume=/dev/b resume_offset=32"),
            Options { resume: Some(b"/dev/b"), resume_offset: 32,
                compressor: None, nocompress: false,
                noresume: false, nohibernate: false });
        assert_eq!(options(b"resume=/dev/a noresume resume=/dev/b resume_offset=9"),
            Options { resume: Some(b"/dev/a"), resume_offset: 0,
                compressor: None, nocompress: false,
                noresume: true, nohibernate: false });
    }

    #[test]
    fn nohibernate_disables_both_directions() {
        assert_eq!(options(b"resume=/dev/a nohibernate resume=/dev/b"),
            Options { resume: Some(b"/dev/a"), resume_offset: 0,
                compressor: None, nocompress: false,
                noresume: true, nohibernate: true });
    }

    #[test]
    fn hibernate_disable_spellings_follow_the_ordered_setup_handler() {
        assert_eq!(options(b"resume=/dev/a hibernate=noresume resume=/dev/b"),
            Options { resume: Some(b"/dev/a"), resume_offset: 0,
                compressor: None, nocompress: false,
                noresume: true, nohibernate: false });
        let disabled = options(b"hibernate=no resume=/dev/b");
        assert!(disabled.noresume);
        assert!(disabled.nohibernate);
        assert_eq!(disabled.resume, None);
    }

    #[test]
    fn malformed_and_inexact_tokens_do_not_mutate_policy() {
        assert_eq!(options(b"xresume=/dev/a noresume=yes resume_offset=x7 resume-offset=8"),
            Options::default());
        assert_eq!(options(b"resume_offset=7x").resume_offset, 7);
    }

    #[test]
    fn compression_selection_is_independent_from_resume_policy() {
        let parsed = options(b"hibernate.compressor=lz4 hibernate=nocompress noresume");
        assert_eq!(parsed.compressor, Some(b"lz4".as_slice()));
        assert!(parsed.nocompress);
        assert!(parsed.noresume);
    }
}
