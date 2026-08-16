//! Commas, colons, and the backslash that hides either.
//!
//! A layer path is an arbitrary path, so both separators can occur inside one.
//! Splitting on every comma turns `lowerdir=/a\,b` into two unusable options,
//! and splitting on every colon turns one layer into two — each of which then
//! fails to resolve, reported as a missing directory rather than as the
//! quoting mistake it is.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use syscall::errno::Errno;

/// Separator between options.
const COMMA: u8 = b',';
/// Separator between lower layers.
const COLON: u8 = b':';
/// Removes the meaning of whichever separator follows.
const ESCAPE: u8 = b'\\';

/// One layer named inside a `lowerdir=` value.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LowerSpec {
    /// Path with escapes still in place; [`unescape`] resolves them.
    pub raw: String,
    /// Reached only through an absolute redirect, never by name.
    pub data_only: bool,
}

/// Take the next option off the front of `s`, honouring backslash escapes, and
/// return it with the remainder. `None` once nothing is left.
///
/// The escape is NOT removed here: it belongs to the value, and only the
/// option that consumes the value knows whether its own grammar has more
/// escaping to do.
/// # C: O(len(token))
pub fn next_opt(s: &str) -> Option<(&str, &str)> {
    if s.is_empty() { return None; }
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == ESCAPE { i += 2; continue; }
        if b[i] == COMMA { return Some((&s[..i], &s[i + 1..])); }
        i += 1;
    }
    Some((s, ""))
}

/// Every option in `s`, split on unescaped commas. # C: O(len(s))
pub fn options(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = s;
    while let Some((tok, next)) = next_opt(rest) {
        if !tok.is_empty() { out.push(tok); }
        rest = next;
        if rest.is_empty() { break; }
    }
    out
}

/// Drop one level of backslash escaping. # C: O(len(s))
pub fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut esc = false;
    for c in s.chars() {
        if esc { out.push(c); esc = false; continue; }
        if c == ESCAPE as char { esc = true; continue; }
        out.push(c);
    }
    out
}

/// Split a `lowerdir=` value into its layers.
///
/// A single unescaped colon separates two merged layers; a double colon starts
/// the data-only layers, which hold file contents that a metadata-only upper
/// object points at. Three colons in a row name nothing, a trailing colon
/// names an empty layer, and a merged layer written after a data-only one
/// could never be reached — each is refused rather than silently dropped,
/// because every one of them silently changes which layer a file comes from.
/// # C: O(len(s))
pub fn split_lowerdirs(s: &str) -> Result<Vec<LowerSpec>, Errno> {
    let mut out: Vec<LowerSpec> = Vec::new();
    if s.is_empty() { return Ok(out); }
    let b = s.as_bytes();
    if b[0] == COLON { return Err(Errno::Einval); }

    let mut seg = String::new();
    let mut i = 0;
    // Whether the separator that ENDED the previous segment was a double
    // colon, which makes the segment now being read a data-only layer.
    let mut data_next = false;
    while i < b.len() {
        if b[i] == ESCAPE {
            seg.push(ESCAPE as char);
            if i + 1 < b.len() { seg.push(b[i + 1] as char); }
            i += 2;
            continue;
        }
        if b[i] != COLON { seg.push(b[i] as char); i += 1; continue; }

        let run = b[i..].iter().take_while(|&&c| c == COLON).count();
        if run > 2 { return Err(Errno::Einval); }
        if i + run == b.len() { return Err(Errno::Einval); }
        push_layer(&mut out, &mut seg, data_next)?;
        // A merged layer may not follow a data-only one: nothing would ever
        // look a name up in it.
        if run == 1 && out.iter().any(|l| l.data_only) { return Err(Errno::Einval); }
        data_next = run == 2;
        i += run;
    }
    push_layer(&mut out, &mut seg, data_next)?;
    Ok(out)
}

/// Record one finished segment, refusing an empty one. # C: O(len(seg))
fn push_layer(out: &mut Vec<LowerSpec>, seg: &mut String, data_only: bool) -> Result<(), Errno> {
    if seg.is_empty() { return Err(Errno::Einval); }
    out.push(LowerSpec { raw: core::mem::take(seg), data_only });
    Ok(())
}
