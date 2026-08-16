// A context as the string userspace reads back.
//
// The rendering is an ABI: userspace compares these strings, stores them in
// filesystem attributes and feeds them back in. Two shapes matter and are easy
// to get subtly wrong — the high level is written ONLY when it differs from
// the low one, and a run of exactly two categories is a comma pair rather than
// a dotted range. Either mistake changes the set a later parse reconstructs.

use alloc::string::{String, ToString};
use core::fmt::Write;

use crate::context::{Context, ValidContext};
use crate::error::{Error, Result};
use crate::mls::{write_cat_list, write_unnamed_cat, Level};
use crate::policydb::Policydb;
use crate::sidtab::{Sid, Sidtab};

/// Separator between the user, role, type and MLS fields.
const FIELD_SEP: char = ':';
/// Separator between the low and high levels of a range.
const LEVEL_SEP: char = '-';

/// Rendered context of one SID. # C: O(categories)
pub fn sid_to_context(db: &Policydb, sidtab: &Sidtab, sid: Sid) -> Result<String> {
    let context = sidtab.search_force(sid).ok_or(Error::UnknownSid)?;
    context_to_string(db, context)
}

/// Rendered form of one context. # C: O(categories)
///
/// A retained unmapped context renders verbatim: it was never interpreted, so
/// there is nothing to re-derive and re-deriving it would lose the original.
pub fn context_to_string(db: &Policydb, c: &Context) -> Result<String> {
    let c = match c {
        Context::Unmapped(s) => return Ok(s.to_string()),
        Context::Valid(c) => c,
    };
    let mut out = String::new();
    out.push_str(name_of(db.symbols.users.iter().find(|u| u.value == c.user).map(|u| &u.name))?);
    out.push(FIELD_SEP);
    out.push_str(name_of(db.symbols.role(c.role).map(|r| &r.name))?);
    out.push(FIELD_SEP);
    out.push_str(name_of(db.symbols.ty(c.ty).map(|t| &t.name))?);
    if !db.mls { return Ok(out); }

    out.push(FIELD_SEP);
    write_level(db, &mut out, &c.range.low)?;
    if !c.range.low.eq_level(&c.range.high) {
        out.push(LEVEL_SEP);
        write_level(db, &mut out, &c.range.high)?;
    }
    Ok(out)
}

/// Rendered form of one valid context. # C: O(categories)
pub fn valid_context_to_string(db: &Policydb, c: &ValidContext) -> Result<String> {
    context_to_string(db, &Context::Valid(c.clone()))
}

fn name_of(name: Option<&String>) -> Result<&str> {
    name.map(String::as_str).ok_or(Error::UnknownSymbol)
}

/// One level: its sensitivity name then its category list.
fn write_level(db: &Policydb, out: &mut String, level: &Level) -> Result<()> {
    let sens = db.symbols.sens_name(level.sens).ok_or(Error::UnknownSymbol)?;
    // The sensitivity name is copied before the categories are appended, so
    // the borrow of the symbol table ends before `out` is written through.
    let sens: String = sens.to_string();
    out.push_str(&sens);
    write_cat_list(out, level, |o, bit| match db.symbols.cat_name(bit) {
        Some(name) => o.write_str(name),
        None => write_unnamed_cat(o, bit),
    }).map_err(|_| Error::Malformed)
}

#[cfg(test)]
#[path = "../tests/render.rs"]
mod tests;
