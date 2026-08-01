// Keyring search — `keyring_search_rcu` + `search_cred_keyrings_rcu`.
//
// The reason this is not a "find the first match" loop: WHY a search failed is
// load-bearing. `request_key` upcalls only when the keyrings were searchable
// and simply held no such key; if the search instead ran into a NEGATIVE key
// for the same type+description, that key's stored errno is returned and no
// upcall happens. That is the entire negative-key caching mechanism — without
// it, a name that cannot be resolved re-runs `/sbin/request-key` on every
// single request. So a skipped key records the reason it was skipped, and the
// reasons are merged across keyrings by a fixed priority.

use alloc::vec::Vec;
use syscall::errno::Errno;

use super::super::perm::{key_task_permission, key_validate};
use super::super::store::{Store, TaskIds};
use super::super::uapi::*;

/// Whether an expired match is skipped silently or reported.
/// `request_key` sets `KEYRING_SEARCH_SKIP_EXPIRED` — an expired key must not
/// stop it from building a fresh one — while `KEYCTL_SEARCH` does not, so a
/// caller asking for a specific key learns it expired rather than that it is
/// missing.
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Expired { Skip, Report }

/// A failed search answers with a RAW errno number rather than an [`Errno`]:
/// a negative key's stored error is whatever `KEYCTL_REJECT` was given, which
/// spans the whole `1..MAX_ERRNO` range and need not be one of the errnos this
/// kernel names. Round-tripping it through an enum would quietly collapse the
/// errors a program branches on into one.
pub type SearchErr = i32;

/// The initial `ctx->result`: the keyrings were searchable and held no match.
/// It is the ONLY outcome that lets `request_key` upcall.
pub const NO_MATCH: SearchErr = Errno::Eagain.as_i32();

/// Walk one keyring recursively for a live, visible type+description match.
///
/// `Err` is the last skip reason, or [`NO_MATCH`] if nothing was skipped —
/// mirroring `ctx->result`, which each skipped candidate overwrites.
/// # C: O(N)
fn search_one(g: &Store, root: i32, t: &TaskIds, key_type: &str, description: &str, now_ns: u64,
    expired: Expired) -> Result<i32, SearchErr>
{
    let mut result = NO_MATCH;
    let mut visited: Vec<i32> = Vec::new();
    let mut stack: Vec<i32> = alloc::vec![root];
    while let Some(cur) = stack.pop() {
        if visited.contains(&cur) { continue; }
        visited.push(cur);
        let ring = match g.keys.get(&cur) { Some(k) if k.is_keyring() => k, _ => continue };
        // A nested keyring the caller cannot search is skipped rather than
        // failing the whole search — Linux records EACCES and keeps going, so
        // one unreachable branch does not hide a match in another.
        if key_validate(ring, now_ns).is_err()
            || key_task_permission(g, ring, t, KEY_NEED_SEARCH).is_err()
        {
            if cur == root { return Err(Errno::Eacces.as_i32()); }
            result = Errno::Eacces.as_i32();
            continue;
        }
        let mut nested: Vec<i32> = Vec::new();
        for &m in &ring.members {
            let k = match g.keys.get(&m) { Some(k) => k, None => continue };
            if k.is_keyring() { nested.push(m); }
            if k.key_type.name != key_type { continue; }
            // State is checked BEFORE the description is compared for the
            // revoked/expired pair, matching the iterator's order.
            if k.invalidated || k.revoked { result = Errno::Ekeyrevoked.as_i32(); continue; }
            if k.expiry_ns != 0 && now_ns >= k.expiry_ns {
                if expired == Expired::Report { result = Errno::Ekeyexpired.as_i32(); }
                continue;
            }
            if k.description != description { continue; }
            if key_task_permission(g, k, t, KEY_NEED_SEARCH).is_err() { result = Errno::Eacces.as_i32(); continue; }
            // A negative key MATCHES but does not satisfy the search: its
            // stored errno becomes the search's answer, which is what stops
            // `request_key` from upcalling again for a name userspace already
            // said it could not resolve.
            if k.is_negative() { result = -k.read_state(); continue; }
            return Ok(m);
        }
        for m in nested.into_iter().rev() { stack.push(m); }
    }
    Err(result)
}

/// `search_cred_keyrings_rcu` over `roots` in order, merging the per-keyring
/// outcomes by Linux's stated priority:
///
/// > success > -ENOKEY > -EAGAIN > other error
///
/// so a negative key found anywhere outranks "nothing here", and both outrank
/// a keyring the caller could not search — a caller must not be told a key is
/// missing when the real answer is that it was denied.
/// # C: O(N)
pub fn search(g: &Store, roots: &[i32], t: &TaskIds, key_type: &str, description: &str,
    now_ns: u64, expired: Expired) -> Result<i32, SearchErr>
{
    let mut ret: Option<SearchErr> = None;
    let mut err = NO_MATCH;
    for &root in roots {
        match search_one(g, root, t, key_type, description, now_ns, expired) {
            Ok(s) => return Ok(s),
            Err(e) if e == Errno::Enokey.as_i32() => ret = Some(e),
            Err(e) if e == NO_MATCH => if ret.is_none() { ret = Some(NO_MATCH); },
            Err(e) => err = e,
        }
    }
    Err(ret.unwrap_or(err))
}
