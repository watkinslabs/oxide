//! Splitting and reading a target's parameter words.
//!
//! Every target constructor parses through here, so the escape rule and the
//! range-check rule exist once. A target that hand-rolled either would be a
//! second grammar for the same table line.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::target::DmResult;

/// Split a parameter string into words. Whitespace separates; a backslash
/// quotes the character after it, so a device name containing a space can be
/// written. A trailing backslash is not an escape — there is nothing after it
/// to quote — and is dropped, which is what makes the loop terminate.
/// # C: O(input.len())
pub fn split_args(input: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut it = input.chars();
    while let Some(c) = it.next() {
        if c == '\\' {
            if let Some(q) = it.next() { cur.push(q); in_word = true; }
            continue;
        }
        if c.is_whitespace() {
            if in_word { out.push(core::mem::take(&mut cur)); in_word = false; }
            continue;
        }
        cur.push(c);
        in_word = true;
    }
    if in_word { out.push(cur); }
    out
}

/// A constructor's remaining words, consumed left to right.
pub struct ArgSet<'a> {
    argv: &'a [&'a str],
    pos: usize,
}

/// The bounds one numeric argument must satisfy, and what to report when it
/// does not. Carrying the message with the bounds is what keeps a refusal
/// reason attached to the rule that produced it.
#[derive(Copy, Clone)]
pub struct Arg {
    /// Smallest accepted value, inclusive.
    pub min: u32,
    /// Largest accepted value, inclusive.
    pub max: u32,
    /// Reason reported when the value is missing, unparsable or out of range.
    pub error: &'static str,
}

impl<'a> ArgSet<'a> {
    /// Start consuming `argv`. # C: O(1)
    pub fn new(argv: &'a [&'a str]) -> Self { Self { argv, pos: 0 } }

    /// Words not yet consumed. # C: O(1)
    pub fn argc(&self) -> usize { self.argv.len() - self.pos }

    /// The words not yet consumed. # C: O(1)
    pub fn rest(&self) -> &'a [&'a str] { &self.argv[self.pos..] }

    /// Take the next word, or `None` at the end. # C: O(1)
    pub fn shift(&mut self) -> Option<&'a str> {
        let w = self.argv.get(self.pos)?;
        self.pos += 1;
        Some(w)
    }

    /// Look at the next word without consuming it. # C: O(1)
    pub fn peek(&self) -> Option<&'a str> { self.argv.get(self.pos).copied() }

    /// Drop `n` words. Consuming past the end is a caller bug, so it is
    /// clamped rather than silently wrapping. # C: O(1)
    pub fn consume(&mut self, n: usize) { self.pos = (self.pos + n).min(self.argv.len()); }

    /// Read one unsigned argument and range-check it. The whole word must be
    /// digits: a trailing character makes it invalid rather than being
    /// ignored, because `4k` meaning four is the sort of leniency that turns a
    /// typo into a wrong chunk size. # C: O(1)
    pub fn read_arg(&mut self, arg: &Arg) -> DmResult<u32> {
        self.read(arg, false)
    }

    /// Read a count that introduces a group, and check the group's words are
    /// actually present. A count larger than the words left is refused here
    /// rather than at the first missing member, which is what stops a
    /// truncated feature list from being read as a shorter valid one.
    /// # C: O(1)
    pub fn read_arg_group(&mut self, arg: &Arg) -> DmResult<u32> {
        self.read(arg, true)
    }

    fn read(&mut self, arg: &Arg, grouped: bool) -> DmResult<u32> {
        let w = self.shift().ok_or(Errno::Einval)?;
        let v: u32 = parse_u32(w).ok_or(Errno::Einval)?;
        if v < arg.min || v > arg.max { return Err(Errno::Einval); }
        if grouped && (self.argc() as u64) < v as u64 { return Err(Errno::Einval); }
        Ok(v)
    }
}

/// Parse a whole word as a decimal `u32`. Rejects an empty word, a sign, and
/// any trailing text. # C: O(s.len())
pub fn parse_u32(s: &str) -> Option<u32> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) { return None; }
    s.parse::<u32>().ok()
}

/// Parse a whole word as a decimal `u64`. # C: O(s.len())
pub fn parse_u64(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) { return None; }
    s.parse::<u64>().ok()
}

/// Parse a `major:minor` pair. Returns `None` for anything else, including a
/// path — the caller falls back to a path lookup, which is the order the
/// reference resolves a device name in. # C: O(s.len())
pub fn parse_devt(s: &str) -> Option<(u32, u32)> {
    let (ma, mi) = s.split_once(':')?;
    Some((parse_u32(ma)?, parse_u32(mi)?))
}
