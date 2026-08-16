// Decimal flags and counts, and the trimming a write needs before parsing.

use alloc::string::String;
use alloc::format;

use vfs::{KResult, VfsError};

/// Text of a write, with the terminators userspace appends removed. # C: O(len)
///
/// A shell redirection appends a newline and a C caller usually writes the
/// terminating NUL. Both are part of what arrives and neither is part of the
/// request, so a parser that did not strip them would refuse every write a
/// real caller makes.
pub fn request_text(body: &[u8]) -> KResult<&str> {
    let text = core::str::from_utf8(body).map_err(|_| VfsError::Einval)?;
    Ok(text.trim_matches(|c: char| c == '\0' || c.is_ascii_whitespace()))
}

/// Parse a written decimal flag; any non-zero value means on. # C: O(len)
///
/// The value is a number, not a word: a write of anything else is refused
/// rather than read as zero, because reading it as zero would silently turn
/// enforcement off for a caller that meant to turn it on.
pub fn parse_flag(s: &str) -> KResult<bool> {
    Ok(parse_i32(s)? != 0)
}

/// Parse a written signed decimal. # C: O(len)
pub fn parse_i32(s: &str) -> KResult<i32> {
    let s = s.trim();
    if s.is_empty() { return Err(VfsError::Einval); }
    s.parse::<i32>().map_err(|_| VfsError::Einval)
}

/// Parse a written unsigned decimal. # C: O(len)
pub fn parse_u32(s: &str) -> KResult<u32> {
    let s = s.trim();
    if s.is_empty() { return Err(VfsError::Einval); }
    s.parse::<u32>().map_err(|_| VfsError::Einval)
}

/// Parse a request's class field. # C: O(len)
///
/// The field is the kernel's decimal class value. Class zero is "no class"
/// and can never be the subject of a question, so it is refused here rather
/// than reaching the engine as a lookup that returns nothing.
pub fn parse_class(s: &str) -> KResult<u16> {
    let v = parse_u32(s)?;
    if v == 0 || v > u16::MAX as u32 { return Err(VfsError::Einval); }
    Ok(v as u16)
}

/// Render a flag the way userspace reads it back. # C: O(1)
pub fn render_flag(on: bool) -> String {
    String::from(if on { "1" } else { "0" })
}

/// Render an unsigned decimal. # C: O(digits)
pub fn render_u32(v: u32) -> String { format!("{v}") }

#[cfg(test)]
#[path = "../tests/format_scalar.rs"]
mod tests;
