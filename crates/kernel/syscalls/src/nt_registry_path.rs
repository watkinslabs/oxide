//! Where one NT key path lands in the registry the owner keeps.
//!
//! The owner holds three hives; a caller names a key by an absolute object
//! path, or relative to a key it already holds. Which hive a path selects,
//! and the status a path that selects none earns, are decided here.

use alloc::string::{String, ToString};

/// Hive selector on the wire to the registry owner.
pub const ROOT_MACHINE: u8 = 0;
pub const ROOT_CURRENT_USER: u8 = 1;
pub const ROOT_CLASSES: u8 = 2;

const STATUS_OBJECT_NAME_NOT_FOUND: u64 = 0xc000_0034;
const STATUS_OBJECT_NAME_INVALID: u64 = 0xc000_0033;
const STATUS_OBJECT_PATH_NOT_FOUND: u64 = 0xc000_003a;
const STATUS_OBJECT_PATH_SYNTAX_BAD: u64 = 0xc000_003b;

const SEPARATOR: char = '\\';
const NAMESPACE: &str = "registry";
const MACHINE: &str = "machine";
const USER: &str = "user";
const CLASSES: &str = "software\\classes";

/// Admit a path given relative to a key the caller already holds. Such a path
/// must not restate the object namespace it is already inside.
/// # C: O(path.len())
pub fn classify_relative(path: &str) -> Result<String, u64> {
    if path.starts_with(SEPARATOR) { return Err(STATUS_OBJECT_PATH_SYNTAX_BAD); }
    reject_empty_component(path)?;
    Ok(path.to_string())
}

/// Select the hive one absolute path names, and the path within it. The
/// caller's spelling is preserved: only the leading components that select
/// the hive are matched without regard to case.
/// # C: O(path.len())
pub fn classify_absolute(path: &str) -> Result<(u8, String), u64> {
    if !path.starts_with(SEPARATOR) { return Err(STATUS_OBJECT_PATH_SYNTAX_BAD); }
    reject_empty_component(&path[1..])?;
    let rest = &path[1..];
    let (head, tail) = split_component(rest);
    if !head.eq_ignore_ascii_case(NAMESPACE) { return Err(missing(tail)); }
    let Some(tail) = tail else { return Err(STATUS_OBJECT_NAME_NOT_FOUND); };
    let (hive, tail) = split_component(tail);
    if hive.eq_ignore_ascii_case(MACHINE) {
        let Some(tail) = tail else { return Ok((ROOT_MACHINE, String::new())); };
        // One hive holds the class registrations that the machine hive also
        // exposes beneath its software key; both spellings name it.
        if tail.len() == CLASSES.len() && tail.eq_ignore_ascii_case(CLASSES) { return Ok((ROOT_CLASSES, String::new())); }
        return match strip_prefix_folded(tail, CLASSES) {
            Some(within) => Ok((ROOT_CLASSES, within.to_string())),
            None => Ok((ROOT_MACHINE, tail.to_string())),
        };
    }
    if hive.eq_ignore_ascii_case(USER) {
        // The component after the user hive selects which user; this system
        // serves one, so it selects that one whatever it spells.
        let Some(tail) = tail else { return Ok((ROOT_CURRENT_USER, String::new())); };
        let (_selector, within) = split_component(tail);
        return Ok((ROOT_CURRENT_USER, within.unwrap_or("").to_string()));
    }
    Err(missing(tail))
}

/// A component that names nothing is a missing path when more path follows it
/// and a missing name when it is the last thing the caller asked for.
fn missing(tail: Option<&str>) -> u64 {
    if tail.is_some() { STATUS_OBJECT_PATH_NOT_FOUND } else { STATUS_OBJECT_NAME_NOT_FOUND }
}

fn reject_empty_component(path: &str) -> Result<(), u64> {
    let mut rest = path;
    while let (head, Some(tail)) = split_component(rest) {
        if head.is_empty() { return Err(STATUS_OBJECT_NAME_INVALID); }
        rest = tail;
    }
    Ok(())
}

fn split_component(path: &str) -> (&str, Option<&str>) {
    match path.find(SEPARATOR) { Some(at) => (&path[..at], Some(&path[at + 1..])), None => (path, None) }
}

fn strip_prefix_folded<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    let boundary = prefix.len() + 1;
    if path.len() <= boundary || !path.is_char_boundary(boundary) { return None; }
    if !path[..prefix.len()].eq_ignore_ascii_case(prefix) || !path[prefix.len()..].starts_with(SEPARATOR) { return None; }
    Some(&path[boundary..])
}

#[cfg(test)]
#[path = "tests/nt_registry_path.rs"]
mod tests;
