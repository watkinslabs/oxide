// The request lines the write and transaction nodes parse.
//
// Fields are separated by whitespace. Each transaction consumes its defined
// prefix and leaves later fields unread; a missing required field is invalid.

use alloc::string::{String, ToString};

use vfs::{KResult, VfsError};

use super::percent::percent_decode;
use super::scalar::parse_class;

/// A request naming a subject, an object and a class.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AvRequest {
    /// Written context of the subject.
    pub scontext: String,
    /// Written context of the object.
    pub tcontext: String,
    /// Class value in the LOADED POLICY's numbering, as `class/<name>/index`
    /// publishes it and userspace writes it back.
    pub class: u16,
}

/// A request for the context of a newly created object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateRequest {
    /// Written context of the creating subject.
    pub scontext: String,
    /// Written context of the parent object.
    pub tcontext: String,
    /// Class value in the LOADED POLICY's numbering, as `class/<name>/index`
    /// publishes it and userspace writes it back.
    pub class: u16,
    /// Name of the object being created, when the caller supplies one.
    pub name: Option<String>,
}

/// A request to validate a relabel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransRequest {
    /// Context the object carries now.
    pub old: String,
    /// Context the object would take.
    pub new: String,
    /// Class value in the LOADED POLICY's numbering, as `class/<name>/index`
    /// publishes it and userspace writes it back.
    pub class: u16,
    /// Context of the task asking.
    pub task: String,
}

/// Take one required whitespace-separated field. # C: O(field)
fn required_field<'a>(fields: &mut core::str::SplitAsciiWhitespace<'a>) -> KResult<&'a str> {
    fields.next().ok_or(VfsError::Einval)
}

/// Parse a `scontext tcontext class` request. # C: O(len)
pub fn parse_access_request(s: &str) -> KResult<AvRequest> {
    let mut f = s.split_ascii_whitespace();
    let scontext = required_field(&mut f)?.to_string();
    let tcontext = required_field(&mut f)?.to_string();
    let class = parse_class(required_field(&mut f)?)?;
    Ok(AvRequest { scontext, tcontext, class })
}

/// Parse a `scontext tcontext class [name]` request. # C: O(len)
///
/// The optional name arrives percent-escaped because a filename may hold the
/// separator this format uses; decoding it here is what keeps a name with a
/// space in it from being read as a fifth field.
pub fn parse_create_request(s: &str) -> KResult<CreateRequest> {
    let mut f = s.split_ascii_whitespace();
    let scontext = required_field(&mut f)?.to_string();
    let tcontext = required_field(&mut f)?.to_string();
    let class = parse_class(required_field(&mut f)?)?;
    let name = match f.next() { Some(n) => Some(percent_decode(n)?), None => None };
    Ok(CreateRequest { scontext, tcontext, class, name })
}

/// Parse an `old new class task` request. # C: O(len)
pub fn parse_validatetrans_request(s: &str) -> KResult<TransRequest> {
    let mut f = s.split_ascii_whitespace();
    let old = required_field(&mut f)?.to_string();
    let new = required_field(&mut f)?.to_string();
    let class = parse_class(required_field(&mut f)?)?;
    let task = required_field(&mut f)?.to_string();
    Ok(TransRequest { old, new, class, task })
}

/// Parse a request that is one context and nothing else. # C: O(len)
pub fn parse_context_request(s: &str) -> KResult<String> {
    let f: alloc::vec::Vec<&str> = s.split_ascii_whitespace().collect();
    if f.len() != 1 { return Err(VfsError::Einval); }
    Ok(f[0].to_string())
}

#[cfg(test)]
#[path = "../tests/format_request.rs"]
mod tests;
