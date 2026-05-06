// Name Service Switch — Linux's `getpwnam` / `getgrnam` /
// `getspnam` reads against `/etc/passwd` / `/etc/group` /
// `/etc/shadow`. v1 implements the file-format parsers as pure
// `&[u8] → struct` functions; the libc-shape glue (`getpwnam_r`,
// `setpwent`/`getpwent`/`endpwent`) lands in a libc shim alongside.
//
// /etc/passwd line:  name:passwd:uid:gid:gecos:home:shell
// /etc/group  line:  name:passwd:gid:user_csv
// /etc/shadow line:  name:hash:lastchg:min:max:warn:inactive:expire:reserved

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(any(test, feature = "hosted"))]
extern crate std;

extern crate alloc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Passwd {
    pub name:   String,
    pub passwd: String,
    pub uid:    u32,
    pub gid:    u32,
    pub gecos:  String,
    pub home:   String,
    pub shell:  String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Group {
    pub name:    String,
    pub passwd:  String,
    pub gid:     u32,
    pub members: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Shadow {
    pub name:        String,
    pub passwd_hash: String,
    pub last_change: i64,    // days since epoch; -1 / "" = unknown
    pub min:         i64,
    pub max:         i64,
    pub warn:        i64,
    pub inactive:    i64,
    pub expire:      i64,
}

fn parse_int(s: &str, default: i64) -> i64 {
    if s.is_empty() { return default; }
    s.parse().unwrap_or(default)
}

fn parse_uint(s: &str, default: u32) -> u32 {
    if s.is_empty() { return default; }
    s.parse().unwrap_or(default)
}

/// Parse one passwd line. Returns None for malformed lines.
/// # C: O(line_len)
pub fn parse_passwd_line(line: &str) -> Option<Passwd> {
    let f: Vec<&str> = line.split(':').collect();
    if f.len() < 7 { return None; }
    Some(Passwd {
        name:   f[0].to_string(),
        passwd: f[1].to_string(),
        uid:    parse_uint(f[2], 0),
        gid:    parse_uint(f[3], 0),
        gecos:  f[4].to_string(),
        home:   f[5].to_string(),
        shell:  f[6].trim_end_matches('\n').to_string(),
    })
}

/// Parse one group line.
/// # C: O(N)
pub fn parse_group_line(line: &str) -> Option<Group> {
    let f: Vec<&str> = line.split(':').collect();
    if f.len() < 4 { return None; }
    let members_raw = f[3].trim_end_matches('\n');
    let members = if members_raw.is_empty() {
        Vec::new()
    } else {
        members_raw.split(',').map(|s| s.to_string()).collect()
    };
    Some(Group {
        name:    f[0].to_string(),
        passwd:  f[1].to_string(),
        gid:     parse_uint(f[2], 0),
        members,
    })
}

/// Parse one shadow line.
/// # C: O(N)
pub fn parse_shadow_line(line: &str) -> Option<Shadow> {
    let f: Vec<&str> = line.split(':').collect();
    if f.len() < 2 { return None; }
    let g = |i: usize| -> i64 {
        if i < f.len() { parse_int(f[i].trim_end_matches('\n'), -1) } else { -1 }
    };
    Some(Shadow {
        name:        f[0].to_string(),
        passwd_hash: f[1].to_string(),
        last_change: g(2),
        min:         g(3),
        max:         g(4),
        warn:        g(5),
        inactive:    g(6),
        expire:      g(7),
    })
}

/// Walk a whole-file `/etc/passwd` byte-blob; return all entries.
/// Skips blank lines + comment lines starting with `#`.
/// # C: O(N)
pub fn parse_passwd(buf: &[u8]) -> Vec<Passwd> {
    let mut out = Vec::new();
    if let Ok(s) = core::str::from_utf8(buf) {
        for ln in s.lines() {
            if ln.is_empty() || ln.starts_with('#') { continue; }
            if let Some(p) = parse_passwd_line(ln) { out.push(p); }
        }
    }
    out
}

/// # C: O(N)
pub fn parse_group(buf: &[u8]) -> Vec<Group> {
    let mut out = Vec::new();
    if let Ok(s) = core::str::from_utf8(buf) {
        for ln in s.lines() {
            if ln.is_empty() || ln.starts_with('#') { continue; }
            if let Some(g) = parse_group_line(ln) { out.push(g); }
        }
    }
    out
}

/// # C: O(N)
pub fn parse_shadow(buf: &[u8]) -> Vec<Shadow> {
    let mut out = Vec::new();
    if let Ok(s) = core::str::from_utf8(buf) {
        for ln in s.lines() {
            if ln.is_empty() || ln.starts_with('#') { continue; }
            if let Some(s) = parse_shadow_line(ln) { out.push(s); }
        }
    }
    out
}

/// `getpwnam` shape — find the first entry matching `name`.
/// # C: O(1)
pub fn getpwnam<'a>(entries: &'a [Passwd], name: &str) -> Option<&'a Passwd> {
    entries.iter().find(|p| p.name == name)
}

/// # C: O(1)
pub fn getpwuid<'a>(entries: &'a [Passwd], uid: u32) -> Option<&'a Passwd> {
    entries.iter().find(|p| p.uid == uid)
}

/// # C: O(1)
pub fn getgrnam<'a>(entries: &'a [Group], name: &str) -> Option<&'a Group> {
    entries.iter().find(|g| g.name == name)
}

/// # C: O(1)
pub fn getgrgid<'a>(entries: &'a [Group], gid: u32) -> Option<&'a Group> {
    entries.iter().find(|g| g.gid == gid)
}

/// # C: O(1)
pub fn getspnam<'a>(entries: &'a [Shadow], name: &str) -> Option<&'a Shadow> {
    entries.iter().find(|s| s.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwd_canonical_line() {
        let p = parse_passwd_line("root:x:0:0:root:/root:/bin/bash").unwrap();
        assert_eq!(p.name, "root");
        assert_eq!(p.uid, 0);
        assert_eq!(p.shell, "/bin/bash");
    }

    #[test]
    fn group_with_members() {
        let g = parse_group_line("wheel:x:10:alice,bob,carol").unwrap();
        assert_eq!(g.gid, 10);
        assert_eq!(g.members, alloc::vec!["alice", "bob", "carol"]);
    }

    #[test]
    fn group_without_members() {
        let g = parse_group_line("nogroup:x:65534:").unwrap();
        assert!(g.members.is_empty());
    }

    #[test]
    fn shadow_canonical() {
        let s = parse_shadow_line("root:$6$abc$xyz:19000:0:99999:7:::").unwrap();
        assert_eq!(s.name, "root");
        assert!(s.passwd_hash.starts_with("$6$"));
        assert_eq!(s.last_change, 19000);
    }

    #[test]
    fn parse_passwd_full_file() {
        let buf = b"# header\nroot:x:0:0:root:/root:/bin/sh\nalice:x:1000:1000:Alice:/home/alice:/bin/sh\n";
        let v = parse_passwd(buf);
        assert_eq!(v.len(), 2);
        assert_eq!(getpwnam(&v, "alice").unwrap().uid, 1000);
        assert!(getpwuid(&v, 999).is_none());
    }

    #[test]
    fn rejects_short_line() {
        assert!(parse_passwd_line("root:x:0").is_none());
        assert!(parse_group_line("wheel:x").is_none());
    }
}
