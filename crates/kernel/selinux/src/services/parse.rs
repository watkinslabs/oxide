// A string from userspace as a context.
//
// Parsing is the inverse of rendering and must stay exactly that: every string
// the engine produces has to parse back to the context it came from, or a
// relabel that reads a label and writes it again quietly changes it. Anything
// the policy does not name is a refusal, never a best guess — a category name
// silently dropped widens the set the object is labelled with.

use alloc::string::{String, ToString};

use crate::context::{Context, ValidContext};
use crate::error::{Error, Result};
use crate::mls::{Level, Range};
use crate::policydb::Policydb;
use crate::sidtab::{Sid, Sidtab};

/// Separator between the user, role, type and MLS fields.
const FIELD_SEP: char = ':';
/// Separator between the low and high levels of a range.
const LEVEL_SEP: char = '-';
/// Separator between the members of a category list.
const CAT_SEP: char = ',';
/// Separator between the ends of an inclusive category run.
const RUN_SEP: char = '.';
/// Fields before the MLS part: user, role and type.
const BASE_FIELDS: usize = 3;

/// Parse a rendered context against the loaded policy. # C: O(categories)
pub fn context_from_string(db: &Policydb, s: &str) -> Result<ValidContext> {
    let mut fields = s.splitn(BASE_FIELDS + 1, FIELD_SEP);
    let (Some(user), Some(role), Some(ty)) = (fields.next(), fields.next(), fields.next())
        else { return Err(Error::Malformed) };
    let mls = fields.next();

    let user = db.symbols.user_by_name(user).ok_or(Error::UnknownSymbol)?;
    let role = db.symbols.role_by_name(role).ok_or(Error::UnknownSymbol)?;
    let ty = db.symbols.type_by_name(ty).ok_or(Error::UnknownSymbol)?;

    let range = match (db.mls, mls) {
        (true, Some(part)) => parse_range(db, part)?,
        (true, None) => return Err(Error::Malformed),
        // A policy without MLS has no vocabulary for a level, so a string
        // carrying one names something this policy cannot mean.
        (false, Some(_)) => return Err(Error::Malformed),
        (false, None) => Range::default(),
    };
    Ok(ValidContext { user, role, ty, range })
}

/// Parse a rendered context and hand back a SID for it. # C: O(categories)
pub fn string_to_sid(db: &Policydb, sidtab: &mut Sidtab, s: &str) -> Result<Sid> {
    let c = context_from_string(db, s)?;
    if !db.context_is_valid(&c) { return Err(Error::InvalidContext); }
    sidtab.context_to_sid(Context::Valid(c))
}

/// Parse the MLS part: one level, or two separated by a dash.
fn parse_range(db: &Policydb, part: &str) -> Result<Range> {
    let mut halves = part.splitn(2, LEVEL_SEP);
    let low_str = halves.next().ok_or(Error::Malformed)?;
    let low = parse_level(db, low_str)?;
    let high = match halves.next() {
        Some(high_str) => parse_level(db, high_str)?,
        None => low.clone(),
    };
    Ok(Range { low, high })
}

/// Parse one level: a sensitivity name and an optional category list.
fn parse_level(db: &Policydb, s: &str) -> Result<Level> {
    let mut parts = s.splitn(2, FIELD_SEP);
    let sens_name = parts.next().ok_or(Error::Malformed)?;
    if sens_name.is_empty() { return Err(Error::Malformed); }
    let sens = db.symbols.sens_by_name(sens_name).ok_or(Error::UnknownSymbol)?;
    let mut level = Level { sens, cat: Default::default() };
    if let Some(cats) = parts.next() { parse_cats(db, cats, &mut level)?; }
    Ok(level)
}

/// Parse a comma-separated category list of single names and inclusive runs.
fn parse_cats(db: &Policydb, s: &str, level: &mut Level) -> Result<()> {
    if s.is_empty() { return Err(Error::Malformed); }
    for item in s.split(CAT_SEP) {
        let mut ends = item.splitn(2, RUN_SEP);
        let head = cat_bit(db, ends.next().ok_or(Error::Malformed)?)?;
        let tail = match ends.next() {
            Some(name) => cat_bit(db, name)?,
            None => head,
        };
        if tail < head { return Err(Error::Malformed); }
        for bit in head..=tail { level.cat.set(bit, true); }
    }
    Ok(())
}

/// Bit position of a named category; policy category values are 1-based.
fn cat_bit(db: &Policydb, name: &str) -> Result<u32> {
    if name.is_empty() { return Err(Error::Malformed); }
    let value = db.symbols.cat_by_name(name).ok_or(Error::UnknownSymbol)?;
    value.checked_sub(1).ok_or(Error::Malformed)
}

/// Rendered-context form of a string, normalised through the policy. # C: O(categories)
///
/// Parsing and re-rendering is what turns a caller-supplied label into the
/// canonical spelling the engine stores, so two spellings of one set cannot
/// become two different SIDs.
pub fn normalise(db: &Policydb, s: &str) -> Result<String> {
    let c = context_from_string(db, s)?;
    super::render::valid_context_to_string(db, &c).map(|s| s.to_string())
}

#[cfg(test)]
#[path = "../tests/parse.rs"]
mod tests;
