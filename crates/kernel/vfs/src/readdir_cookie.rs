// Stable readdir cookies for the synthetic filesystems (Linux fs/kernfs/dir.c).
//
// An ORDINAL cursor ("I emitted 7 entries, resume at 7") is not a `d_off`
// cookie. `getdents` is paginated, so a create/unlink between two calls shifts
// every later ordinal: the listing then DUPLICATES or SKIPS entries, and a
// `seekdir(3)` cookie taken before the mutation names a different entry after
// it. Linux solves this by keeping kernfs children in a tree ordered by a hash
// of the NAME and making `ctx->pos` that hash — a cookie derived only from the
// entry itself, so it survives any mutation of its neighbours.
//
// This module is the one place that cookie space is defined, so every synthetic
// backend (devfs, devpts, sysfs, procfs, tracefs/debugfs, cgroupfs, tmpfs,
// binfmt_misc) shares one contract instead of ~50 hand-rolled index loops.
//
// Cookie contract:
//   * `0` / `1` are `.` / `..` (`crate::dirent::DOTS_RESERVED`), never a child.
//   * a child's cookie is [`name_cookie`] of its name, in `[COOKIE_MIN, COOKIE_MAX]`.
//   * entries are emitted in ASCENDING cookie order, ties broken by name.
//   * the resume cursor stored after an entry is `cookie + 1`, so a listing
//     resumes at "the first child whose cookie is >= the stored value".
//
// Ungated: every decision here is hosted-testable.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use crate::file_ops::DirContext;
use crate::types::{FileType, KResult};

/// Lowest cookie a child may take. `0`/`1` belong to `.`/`..`, exactly as Linux
/// kernfs reserves hash values 0 and 1 for the same two entries.
pub const COOKIE_MIN: u64 = crate::dirent::DOTS_RESERVED;

/// Highest cookie a child may take. Bounded well below `u64::MAX` so the
/// `cookie + 1` resume cursor, and the `+ DOTS_RESERVED` shift the dots wrapper
/// applies on the way out, cannot wrap.
pub const COOKIE_MAX: u64 = 1 << 62;

/// FNV-1a 64 offset basis / prime — a name hash, not a security primitive.
const FNV64_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV64_PRIME: u64 = 0x0000_0100_0000_01b3;

/// Cookie for a directory entry NAME (Linux kernfs `kernfs_name_hash`): a hash
/// of the name alone, so it does not move when a sibling is created or removed.
/// Folded into `[COOKIE_MIN, COOKIE_MAX]` so the reserved dot cursors and the
/// `+1` resume arithmetic stay out of range. # C: O(len)
pub fn name_cookie(name: &str) -> u64 {
    let mut h = FNV64_BASIS;
    for b in name.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(FNV64_PRIME);
    }
    COOKIE_MIN + (h % (COOKIE_MAX - COOKIE_MIN))
}

/// One directory entry ready to emit under the cookie contract.
pub struct CookieEntry {
    /// Assigned position. Seeded from [`name_cookie`]; [`emit_by_cookie`] may
    /// nudge it upward to break a hash collision.
    pub cookie: u64,
    pub name: String,
    pub ino: u64,
    pub d_type: FileType,
}

impl CookieEntry {
    /// Entry at its name's natural cookie. # C: O(len)
    pub fn new(name: String, ino: u64, d_type: FileType) -> Self {
        Self { cookie: name_cookie(&name), name, ino, d_type }
    }
}

/// Order `entries` by cookie (ties by name) and give every entry a DISTINCT
/// cookie by nudging a collided one to `previous + 1`. Two names sharing a
/// 64-bit hash is the only case this touches; without it a collided pair would
/// re-emit or skip within its own group. # C: O(N log N)
pub fn order_by_cookie(entries: &mut [CookieEntry]) {
    entries.sort_by(|a, b| a.cookie.cmp(&b.cookie).then_with(|| a.name.cmp(&b.name)));
    let mut prev: Option<u64> = None;
    for e in entries.iter_mut() {
        if let Some(p) = prev {
            if e.cookie <= p { e.cookie = p + 1; }
        }
        prev = Some(e.cookie);
    }
}

/// Emit every entry at or after `ctx.pos` in cookie order, storing `cookie + 1`
/// as the resume cursor. Reordering happens here so a caller only has to
/// collect `(name, ino, d_type)`.
///
/// This is the whole point of the cookie: entries created or removed between
/// two `getdents` calls change nothing about the cookies of the entries that
/// remain, so a paginated listing neither duplicates nor skips. # C: O(N log N)
pub fn emit_by_cookie(entries: &mut Vec<CookieEntry>, ctx: &mut DirContext) -> KResult<()> {
    order_by_cookie(entries);
    for e in entries.iter() {
        if e.cookie < ctx.pos { continue; }
        if !ctx.emit(&e.name, e.ino, e.d_type, e.cookie + 1) { break; }
    }
    Ok(())
}
