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

use super::super::auth;
use super::super::perm::{key_task_permission, key_validate};
use super::super::store::{Store, TaskIds};
use super::super::uapi::*;

fn decode_hex(id: &str) -> Option<Vec<u8>> {
    if id.is_empty() || id.len() % 2 != 0 { return None; }
    let mut out = Vec::with_capacity(id.len() / 2);
    for pair in id.as_bytes().chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

fn asymmetric_match(ids: &[Vec<u8>], name_id: Option<&[u8]>, description: &str) -> bool {
    let Some((kind, text)) = description.split_once(':') else { return false; };
    let Some(want) = decode_hex(text) else { return false; };
    match kind {
        "id" => ids.iter().any(|id| id.ends_with(&want)),
        "ex" => ids.iter().any(|id| id == &want),
        "dn" => name_id.is_some_and(|id| id == want),
        _ => false,
    }
}

fn asymmetric_selector(description: &str) -> bool {
    description.starts_with("id:") || description.starts_with("ex:") || description.starts_with("dn:")
}

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
            || key_task_permission(g, ring, t, KEY_NEED_SEARCH, now_ns).is_err()
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
            if k.key_type.name == ASYMMETRIC_KEY_TYPE {
                if asymmetric_selector(description)
                    && !asymmetric_match(&k.asymmetric_ids, k.asymmetric_name_id.as_deref(), description)
                { continue; }
                if !asymmetric_selector(description) && k.description != description { continue; }
            } else if k.description != description { continue; }
            if key_task_permission(g, k, t, KEY_NEED_SEARCH, now_ns).is_err() { result = Errno::Eacces.as_i32(); continue; }
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

/// `search_process_keyrings_rcu`: [`search`] over the caller's OWN keyrings,
/// and then — when the caller is servicing an upcall — over the REQUESTER's,
/// under the requester's credentials.
///
/// The second half is what makes a construction helper able to see the keys of
/// the task it is building for: `/sbin/request-key` runs as a fresh process
/// with nothing but its own request keyring, so a handler that needs the
/// requester's ticket cache or its parent key would otherwise find nothing.
/// The authority to reach them is exactly the token, which is why the reach
/// disappears the moment the key is answered.
///
/// A token is deliberately NOT reachable this way: a helper may only act under
/// the token it was handed directly, never under one it found by searching the
/// requester it is servicing.
///
/// The two outcomes merge by `success > -ENOKEY > -EAGAIN > other error`, the
/// same priority [`search`] uses across keyrings — so a negative key in either
/// half outranks "nothing here", and a denial only survives when the other
/// half had nothing better to say.
/// # C: O(N)
pub fn search_process(g: &Store, t: &TaskIds, key_type: &str, description: &str, now_ns: u64,
    expired: Expired) -> Result<i32, SearchErr>
{
    let own = g.cred_roots(t);
    let err = match search(g, &own, t, key_type, description, now_ns, expired) {
        Ok(s) => return Ok(s),
        Err(e) => e,
    };
    let mut ret = Errno::Eacces.as_i32();
    if key_type != REQKEY_AUTH_TYPE {
        if let Some(rq) = auth::assumed_requester(g, t, now_ns) {
            let roots = g.cred_roots(&rq);
            match search(g, &roots, &rq, key_type, description, now_ns, expired) {
                Ok(s) => return Ok(s),
                Err(e) => ret = e,
            }
        }
    }
    let enokey = Errno::Enokey.as_i32();
    if err == enokey || ret == enokey { return Err(enokey); }
    Err(if err == Errno::Eacces.as_i32() { ret } else { err })
}
