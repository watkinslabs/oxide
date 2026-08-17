// The request lines the write and transaction nodes parse.
//
// Fields are separated by whitespace and the count is exact. A parser that
// accepted a missing or extra field would answer a question the caller did
// not ask: the same three words with a fourth appended is a different query,
// and a request one field short would silently shift the class into the
// target's place.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

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

/// Split a request into its whitespace-separated fields. # C: O(len)
fn fields(s: &str) -> Vec<&str> { s.split_ascii_whitespace().collect() }

/// Parse a `scontext tcontext class` request. # C: O(len)
pub fn parse_access_request(s: &str) -> KResult<AvRequest> {
    let f = fields(s);
    if f.len() != 3 { return Err(VfsError::Einval); }
    Ok(AvRequest { scontext: f[0].to_string(), tcontext: f[1].to_string(),
                   class: parse_class(f[2])? })
}

/// Parse a `scontext tcontext class [name]` request. # C: O(len)
///
/// The optional name arrives percent-escaped because a filename may hold the
/// separator this format uses; decoding it here is what keeps a name with a
/// space in it from being read as a fifth field.
pub fn parse_create_request(s: &str) -> KResult<CreateRequest> {
    let f = fields(s);
    if f.len() != 3 && f.len() != 4 { return Err(VfsError::Einval); }
    let name = match f.get(3) { Some(n) => Some(percent_decode(n)?), None => None };
    Ok(CreateRequest { scontext: f[0].to_string(), tcontext: f[1].to_string(),
                       class: parse_class(f[2])?, name })
}

/// Parse an `old new class task` request. # C: O(len)
pub fn parse_validatetrans_request(s: &str) -> KResult<TransRequest> {
    let f = fields(s);
    if f.len() != 4 { return Err(VfsError::Einval); }
    Ok(TransRequest { old: f[0].to_string(), new: f[1].to_string(),
                      class: parse_class(f[2])?, task: f[3].to_string() })
}

/// Parse a request that is one context and nothing else. # C: O(len)
pub fn parse_context_request(s: &str) -> KResult<String> {
    let f = fields(s);
    if f.len() != 1 { return Err(VfsError::Einval); }
    Ok(f[0].to_string())
}

#[cfg(test)]
#[path = "../tests/format_request.rs"]
mod tests;
