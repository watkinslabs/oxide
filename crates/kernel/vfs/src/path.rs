// Path component splitter per `16§3`. Mirrors POSIX semantics:
// repeated `/` collapse, leading `/` ⇒ absolute, trailing `/` is
// ignored, `.` is dropped, `..` walks up (the caller decides what
// "up" means at the root or at a mount boundary).
//
// Symlink resolution + RESOLVE_BENEATH / RESOLVE_NO_SYMLINKS / mount
// crossing all live in the future `path_lookup` (`16§3`); this module
// only does the lexical split.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Component<'a> {
    Root,
    Normal(&'a str),
    ParentDir, // ..
}

/// Split `path` into components per POSIX. Empty or `.`-only segments
/// are skipped.
/// # C: O(len)
pub fn components(path: &str) -> Vec<Component<'_>> {
    let mut out = Vec::new();
    let mut start = 0usize;
    if path.as_bytes().first() == Some(&b'/') {
        out.push(Component::Root);
    }
    let bytes = path.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'/' {
            if start < i {
                push_segment(&mut out, &path[start..i]);
            }
            i += 1;
            start = i;
        } else {
            i += 1;
        }
    }
    if start < bytes.len() {
        push_segment(&mut out, &path[start..]);
    }
    out
}

fn push_segment<'a>(out: &mut Vec<Component<'a>>, seg: &'a str) {
    match seg {
        "" | "."   => {} // skip
        ".."       => out.push(Component::ParentDir),
        s          => out.push(Component::Normal(s)),
    }
}

/// Linux per-component name limit (`NAME_MAX`, `linux/limits.h`): the longest
/// single pathname component a filesystem accepts is 255 *bytes* (not scalar
/// values). `link_path_walk`/`walk_component` reject a longer component with
/// `ENAMETOOLONG` even when the whole pathname is well under `PATH_MAX` (the
/// total-length gate, enforced separately at the syscall boundary).
pub const NAME_MAX: usize = 255;

/// On-disk byte length of a (possibly escape-decoded) component name. Each
/// escaped non-UTF-8 byte (`U+EE00..=U+EEFF`, see [`path_from_bytes`])
/// collapses to the one byte it stands for; every other char counts its UTF-8
/// length. Matches what a backend compares against on-disk names, so the
/// `NAME_MAX` check is byte-accurate even for non-UTF-8 names — no allocation.
/// # C: O(n)
fn component_byte_len(name: &str) -> usize {
    let mut n = 0usize;
    for c in name.chars() {
        let u = c as u32;
        if (BYTE_ESCAPE_BASE..=BYTE_ESCAPE_BASE + 0xFF).contains(&u) { n += 1; }
        else { n += c.len_utf8(); }
    }
    n
}

/// Enforce `NAME_MAX` on a single pathname component, mirroring the Linux
/// walk's per-component check. `Ok(())` when `name` is ≤ `NAME_MAX` on-disk
/// bytes, else `Enametoolong`. Reusable primitive: the walker validates one
/// component at a time as it descends.
/// # C: O(name.len())
pub fn check_component(name: &str) -> Result<(), crate::types::VfsError> {
    if component_byte_len(name) > NAME_MAX { Err(crate::types::VfsError::Enametoolong) } else { Ok(()) }
}

/// [`components`] plus the Linux per-component `NAME_MAX` gate: split `path`
/// and reject (`Enametoolong`) the moment any `Normal` component exceeds
/// `NAME_MAX` bytes. `/`, `.`, `..` control segments are exempt (none names a
/// file). Total-path length is NOT checked here — that is `PATH_MAX`'s job at
/// the syscall boundary (`read_user_path`).
/// # C: O(len)
pub fn components_checked(path: &str) -> Result<Vec<Component<'_>>, crate::types::VfsError> {
    let parts = components(path);
    for c in &parts {
        if let Component::Normal(s) = c { check_component(s)?; }
    }
    Ok(parts)
}

/// True iff `path` is absolute (begins with `/`).
/// # C: O(1)
pub fn is_absolute(path: &str) -> bool {
    path.as_bytes().first() == Some(&b'/')
}

/// Linux `LOOKUP_DIRECTORY` derived from pathname *syntax*: true when `path`
/// forces its resolved target to be a directory by construction. Three forms
/// (`link_path_walk`): a trailing `/` (one or more — `foo/`), or a final `.`
/// (`foo/.`), or a final `..` (`foo/..`). Each only resolves against a
/// directory, so a non-dir leaf is `ENOTDIR` (`/etc/passwd/`, `/etc/passwd/.`,
/// `/etc/passwd/..` all fail). The bare root `/` (len 1) IS the root directory
/// and imposes nothing extra. Companion to [`components`], which drops the
/// trailing `/` and `.` and so cannot itself carry this requirement.
/// # C: O(len)
pub fn requires_dir(path: &str) -> bool {
    match path.as_bytes().last() {
        None        => false,              // empty path
        Some(&b'/') => path.len() > 1,     // trailing slash, non-root
        Some(_)     => matches!(path.rsplit('/').next(), Some("." | "..")),
    }
}

/// Private-use code-point base for escaped non-UTF-8 path bytes. Each
/// raw byte `b` of an invalid UTF-8 sequence maps to `U+EE00 + b`
/// (PUA-A, valid Rust scalar values). `path_into_bytes` reverses it.
const BYTE_ESCAPE_BASE: u32 = 0xEE00;

/// Decode an opaque pathname byte string (Linux paths are byte strings,
/// NOT guaranteed UTF-8 — see `path_resolution(7)`) into a Rust `String`
/// that round-trips back to the exact bytes via [`path_into_bytes`].
///
/// Valid UTF-8 is kept verbatim, so a backend comparing `name.as_bytes()`
/// against an on-disk name still matches byte-for-byte in the common case.
/// Each byte of an *invalid* UTF-8 sequence is escaped to `U+EE00 + byte`
/// (a "lossy-but-byte-preserving" surrogate-escape; Rust `String` cannot
/// hold bare invalid bytes or surrogates). Ambiguity only arises if the
/// input legitimately contained a `U+EE00..=U+EEFF` scalar, which is
/// vanishingly rare in real pathnames.
/// # C: O(n)
pub fn path_from_bytes(bytes: &[u8]) -> String {
    // Fast path: already valid UTF-8 → no allocation churn beyond the copy.
    if let Ok(s) = core::str::from_utf8(bytes) { return String::from(s); }
    let mut out = String::new();
    let mut i = 0usize;
    while i < bytes.len() {
        match core::str::from_utf8(&bytes[i..]) {
            Ok(s) => { out.push_str(s); break; }
            Err(e) => {
                let valid = e.valid_up_to();
                // SAFETY: from_utf8 validated bytes[i..i+valid] as UTF-8 above.
                out.push_str(unsafe { core::str::from_utf8_unchecked(&bytes[i..i + valid]) });
                i += valid;
                let bad = e.error_len().unwrap_or(bytes.len() - i);
                for j in 0..bad {
                    let b = bytes[i + j];
                    // unwrap: BASE+255 = 0xEEFF, a valid scalar value.
                    out.push(char::from_u32(BYTE_ESCAPE_BASE + b as u32).unwrap());
                }
                i += bad;
            }
        }
    }
    out
}

/// Inverse of [`path_from_bytes`]: turn an escaped path `String` back into
/// the original opaque pathname bytes a backend compares against on-disk
/// names. Escaped scalars (`U+EE00..=U+EEFF`) collapse to their single
/// byte; every other char emits its UTF-8 encoding.
/// # C: O(n)
pub fn path_into_bytes(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    for c in s.chars() {
        let u = c as u32;
        if (BYTE_ESCAPE_BASE..=BYTE_ESCAPE_BASE + 0xFF).contains(&u) {
            out.push((u - BYTE_ESCAPE_BASE) as u8);
        } else {
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
        }
    }
    out
}

/// Trim trailing newlines + NULs from a hostname-shaped byte slice
/// and clamp to `max`. Used by the global hostname slot per
/// `28§4` / sethostname(2). `echo "host" > /proc/sys/kernel/hostname`
/// passes a trailing newline that must be stripped.
/// # C: O(N)
pub fn trim_hostname<'a>(input: &'a [u8], max: usize) -> &'a [u8] {
    let mut end = input.len().min(max);
    while end > 0 && matches!(input[end - 1], b'\n' | 0) { end -= 1; }
    &input[..end]
}

/// Resolve `path` against `cwd`. If `path` is absolute, returns
/// the lexically-normalized form. Otherwise joins as `cwd/path`
/// then normalizes. `cwd` must itself be absolute.
/// # C: O(len)
pub fn resolve_against_cwd(cwd: &str, path: &str) -> Option<String> {
    if is_absolute(path) {
        return lexical_normalize(path);
    }
    let mut joined = String::with_capacity(cwd.len() + 1 + path.len());
    joined.push_str(cwd);
    if !cwd.ends_with('/') { joined.push('/'); }
    joined.push_str(path);
    lexical_normalize(&joined)
}

/// Parse `/proc/{self|<pid>}/fd/<n>` → `(tid_opt, fd)` (`self` ⇒
/// `None`). The Linux magic-fd-link reopen/readlink contract: opening
/// or stat-ing this path acts on the open file description fd `<n>`
/// already holds. Returns `None` when the shape doesn't match.
/// # C: O(N_path)
/// `Some(rest)` if `s` begins with the literal `p` (byte compare, no
/// string-prefix combinator). Magic pseudo-path parsing only — never a
/// mount-tree containment test. # C: O(len p)
fn rest_after<'a>(s: &'a str, p: &str) -> Option<&'a str> {
    let (sb, pb) = (s.as_bytes(), p.as_bytes());
    if sb.len() >= pb.len() && &sb[..pb.len()] == pb { Some(&s[pb.len()..]) } else { None }
}

pub fn parse_proc_fd(path: &str) -> Option<(Option<u32>, i32)> {
    let rest = rest_after(path, "/proc/")?;
    let mut it = rest.splitn(3, '/');
    let who = it.next()?;
    if it.next()? != "fd" { return None; }
    let fd: i32 = it.next()?.parse().ok()?;
    let tid = if who == "self" { None } else { Some(who.parse::<u32>().ok()?) };
    Some((tid, fd))
}

/// Map any path that resolves by **duplicating an existing open file
/// description** → `(tid_opt, fd)`. The Linux fd-link open family:
/// `/dev/std{in,out,err}` (fd 0/1/2), `/dev/fd/<n>`, and
/// `/proc/{self|<pid>}/fd/<n>`. `None` otherwise (resolve normally).
/// # C: O(N_path)
pub fn dup_fd_target(path: &str) -> Option<(Option<u32>, i32)> {
    match path {
        "/dev/stdin"  => return Some((None, 0)),
        "/dev/stdout" => return Some((None, 1)),
        "/dev/stderr" => return Some((None, 2)),
        _ => {}
    }
    if let Some(rest) = rest_after(path, "/dev/fd/") {
        return rest.parse::<i32>().ok().map(|n| (None, n));
    }
    parse_proc_fd(path)
}

/// Normalize a path lexically (collapse `.` and interior `x/..`).
/// Does NOT consult the FS. Absolute paths clamp parent walks at `/`,
/// matching Linux path walk (`/.. == /`). Relative paths PRESERVE
/// leading `..` components (`../../a` stays `../../a`): on a relative
/// path `..` is only resolvable per-component against the live tree
/// after mount/symlink crossing, never lexically (`path_resolution(7)`).
/// # C: O(len)
pub fn lexical_normalize(path: &str) -> Option<String> {
    let mut stack: Vec<&str> = Vec::new();
    let abs = is_absolute(path);
    for c in components(path) {
        match c {
            Component::Root      => {} // absolute already implied; ignore
            Component::Normal(s) => stack.push(s),
            Component::ParentDir => {
                // Only collapse `..` against a *real* preceding name. A
                // leading `..` on a relative path is NOT lexically
                // resolvable (Linux resolves `..` per-component AFTER
                // mount/symlink against the live tree), so it must be
                // preserved — and a later `..` must NOT pop it.
                match stack.last() {
                    Some(&top) if top != ".." => { stack.pop(); }
                    _ => { if !abs { stack.push(".."); } } // abs: clamp at root
                }
            }
        }
    }
    let mut out = String::new();
    if abs { out.push('/'); }
    for (i, s) in stack.iter().enumerate() {
        if i > 0 { out.push('/'); }
        out.push_str(s);
    }
    if out.is_empty() { out.push('.'); }
    Some(out)
}
