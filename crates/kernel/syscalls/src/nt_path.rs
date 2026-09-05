//! Windows NT path translation into the kernel VFS namespace.

extern crate alloc;
use alloc::string::String;

/// Lookup policy for every native Windows pathname walk. The VFS keeps the
/// dentry's stored name as its display spelling while its owning filesystem
/// applies the Unicode equivalence rule to the query.
/// # C: O(1)
pub(crate) fn windows_lookup_flags() -> vfs::LookupFlags {
    vfs::LookupFlags { case_insensitive: true, ..Default::default() }
}

/// Decode one NT `UNICODE_STRING` payload after the user copy. Unpaired
/// surrogates are malformed; valid pairs become one Rust scalar so the VFS
/// receives the supplied Unicode name.
pub(crate) fn decode_utf16(units: &[u16]) -> Option<String> {
    let mut output = String::new();
    let mut index = 0;
    while index < units.len() {
        let unit = units[index];
        let scalar = if (0xd800..=0xdbff).contains(&unit) {
            let next = *units.get(index + 1)?;
            if !(0xdc00..=0xdfff).contains(&next) { return None; }
            index += 1;
            0x1_0000 + (((unit - 0xd800) as u32) << 10) + (next - 0xdc00) as u32
        } else if (0xdc00..=0xdfff).contains(&unit) {
            return None;
        } else { unit as u32 };
        output.push(core::char::from_u32(scalar)?);
        index += 1;
    }
    Some(output)
}

/// Translate an absolute DOS/NT path to the Windows VFS root.
///
/// Drive-relative paths such as `C:foo` are deliberately rejected until the
/// runtime has a per-drive current-directory table.  Treating them as
/// `C:\\foo` would silently open a different file than Windows does.
pub fn normalize_path(raw: &str) -> Option<String> {
    if raw.chars().any(|c| c == '\0') { return None; }
    let path = raw.replace('\\', "/");
    let path = path
        .strip_prefix("/??/")
        .or_else(|| path.strip_prefix("/DosDevices/"))
        .unwrap_or(&path);
    let path = if path.get(..4).is_some_and(|prefix| prefix.eq_ignore_ascii_case("UNC/")) {
        return normalize_unc(&path[4..]);
    } else if path.get(..8).is_some_and(|prefix| prefix.eq_ignore_ascii_case("//?/UNC/"))
        || path.get(..8).is_some_and(|prefix| prefix.eq_ignore_ascii_case("//./UNC/")) {
        return normalize_unc(&path[7..]);
    } else { path };
    if path.starts_with("//") { return normalize_unc(&path[2..]); }
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' {
        if !bytes[0].is_ascii_alphabetic() || bytes.get(2) != Some(&b'/') {
            return None;
        }
        let drive = (bytes[0] as char).to_ascii_lowercase();
        let mut translated = String::from("/windows/");
        translated.push(drive);
        translated.push_str(&path[2..]);
        return lexical_normalize(&translated);
    }
    lexical_normalize(&path)
}

/// Translate an NT object name that has no `RootDirectory`.  NT object
/// attributes without a root name an absolute object, never the caller's
/// Linux current directory. # C: O(path length)
pub fn normalize_absolute_path(raw: &str) -> Option<String> {
    let path = normalize_path(raw)?;
    path.starts_with('/').then_some(path)
}

fn normalize_unc(path: &str) -> Option<String> {
    let mut components = path.split('/').filter(|part| !part.is_empty());
    let server = components.next()?;
    let share = components.next()?;
    if matches!(server, "." | "..") || matches!(share, "." | "..") { return None; }
    let suffix_parts = components.collect::<alloc::vec::Vec<_>>();
    let mut translated = String::from("/windows/unc/");
    translated.push_str(server);
    translated.push('/');
    translated.push_str(share);
    let suffix = suffix_parts.join("/");
    if !suffix.is_empty() {
        let suffix = lexical_normalize(&suffix)?;
        if suffix == ".." || suffix.starts_with("../") { return None; }
        if suffix != "." { translated.push('/'); translated.push_str(suffix.trim_start_matches('/')); }
    }
    Some(translated)
}

/// Render a canonical VFS path in the DOS spelling exposed by NT file
/// information replies.  The drive and UNC mounts are owned by this layer;
/// other absolute paths retain their root while adopting Windows separators.
pub fn render_windows_path(path: &str) -> Option<String> {
    if path.as_bytes().contains(&0) { return None; }
    if let Some(rest) = path.strip_prefix("/windows/unc/") {
        if rest.is_empty() { return None; }
        let mut output = String::from("\\\\");
        output.push_str(&rest.replace('/', "\\"));
        return Some(output);
    }
    if let Some(rest) = path.strip_prefix("/windows/") {
        let mut parts = rest.splitn(2, '/');
        let drive = parts.next()?;
        if drive.len() != 1 || !drive.as_bytes()[0].is_ascii_alphabetic() { return None; }
        let mut output = String::new();
        output.push(drive.as_bytes()[0].to_ascii_uppercase() as char);
        output.push(':');
        output.push('\\');
        if let Some(rest) = parts.next() { output.push_str(&rest.replace('/', "\\")); }
        return Some(output);
    }
    Some(path.replace('/', "\\"))
}

/// Join a normalized relative NT name to a VFS directory path. Absolute names
/// remain rooted and therefore do not inherit the supplied directory. # C: O(path)
pub fn join_root_path(root: &str, relative: &str) -> Option<String> {
    if root.is_empty() || relative.is_empty() || relative.starts_with('/') { return None; }
    let mut joined = String::from(root);
    if !joined.ends_with('/') { joined.push('/'); }
    joined.push_str(relative);
    normalize_path(&joined)
}

/// Resolve an NT object name against its `RootDirectory` path. Absolute names
/// retain NT's root precedence; relative names require a directory root and
/// are joined through the canonical VFS path normalizer. # C: O(path)
pub fn resolve_object_path(root: Option<&str>, raw: &str) -> Option<String> {
    let path = normalize_path(raw)?;
    if path.starts_with('/') { return Some(path); }
    join_root_path(root?, &path)
}

fn lexical_normalize(path: &str) -> Option<String> {
    let absolute = path.starts_with('/');
    let drive_floor = if absolute && path.get(..9).is_some_and(|prefix| prefix.eq_ignore_ascii_case("/windows/")) {
        let rest = &path[9..];
        (rest.as_bytes().first().is_some_and(|drive| drive.is_ascii_alphabetic()) && rest.as_bytes().get(1) == Some(&b'/'))
            .then_some(2)
    } else { None };
    let mut parts: alloc::vec::Vec<&str> = alloc::vec::Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => match parts.last() {
                Some(last) if *last != ".." && drive_floor.is_none_or(|floor| parts.len() > floor) => { parts.pop(); }
                Some(_) if drive_floor.is_some_and(|floor| parts.len() <= floor) => return None,
                _ if !absolute => parts.push(".."),
                _ => {}
            },
            value => parts.push(value),
        }
    }
    let mut normalized = String::new();
    if absolute { normalized.push('/'); }
    for (index, part) in parts.iter().enumerate() {
        if index != 0 { normalized.push('/'); }
        normalized.push_str(part);
    }
    if normalized.is_empty() { normalized.push(if absolute { '/' } else { '.' }); }
    Some(normalized)
}

#[cfg(test)]
mod tests {
    use alloc::string::String;
    use super::{join_root_path, normalize_absolute_path, normalize_path, render_windows_path,
        resolve_object_path, windows_lookup_flags};

    #[test]
    fn native_windows_lookup_uses_unicode_case_insensitive_vfs_policy() {
        let flags = windows_lookup_flags();
        assert!(flags.case_insensitive);
    }

    #[test]
    fn maps_absolute_drive_paths_to_windows_root() {
        assert_eq!(normalize_path(r"C:\Games\Example\data.pak"),
            Some(String::from("/windows/c/Games/Example/data.pak")));
        assert_eq!(normalize_path(r"\??\D:\Temp\note.txt"),
            Some(String::from("/windows/d/Temp/note.txt")));
    }

    #[test]
    fn maps_dos_and_nt_unc_paths_to_one_canonical_vfs_root() {
        assert_eq!(normalize_path(r"\\server\Share\Games\data.pak"),
            Some(String::from("/windows/unc/server/Share/Games/data.pak")));
        assert_eq!(normalize_path(r"\??\UNC\server\Share\Games\data.pak"),
            Some(String::from("/windows/unc/server/Share/Games/data.pak")));
        assert_eq!(normalize_path(r"\\?\UNC\server\Share\Games\data.pak"),
            Some(String::from("/windows/unc/server/Share/Games/data.pak")));
        assert_eq!(normalize_path(r"\\server\Share\Games\.\Demo\..\data.pak"),
            Some(String::from("/windows/unc/server/Share/Games/data.pak")));
    }

    #[test]
    fn rejects_unc_paths_without_server_and_share() {
        assert_eq!(normalize_path(r"\\"), None);
        assert_eq!(normalize_path(r"\\server"), None);
        assert_eq!(normalize_path(r"\\server\..\data"), None);
    }

    #[test]
    fn preserves_non_drive_absolute_paths() {
        assert_eq!(normalize_path(r"\Device\Null"), Some(String::from("/Device/Null")));
        assert_eq!(normalize_path(r"\DosDevices\C:\"),
            Some(String::from("/windows/c")));
    }

    #[test]
    fn rejects_drive_relative_paths() {
        assert_eq!(normalize_path(r"C:relative.txt"), None);
        assert_eq!(normalize_path(r"1:\invalid"), None);
    }

    #[test]
    fn collapses_windows_dot_segments_without_escaping_the_drive_root() {
        assert_eq!(normalize_path(r"C:\Games\.\Demo\..\data.pak"),
            Some(String::from("/windows/c/Games/data.pak")));
        assert_eq!(normalize_path(r"C:\..\..\data.pak"), None);
        assert_eq!(normalize_path(r"C:\Games\\data.pak"),
            Some(String::from("/windows/c/Games/data.pak")));
    }

    #[test]
    fn rejects_embedded_nul_before_vfs_lookup() {
        assert_eq!(normalize_path("C:\\Games\\bad\0name"), None);
    }

    #[test]
    fn rejects_relative_object_names_without_a_root_directory() {
        assert_eq!(normalize_absolute_path("notepad.exe"), None);
        assert_eq!(normalize_absolute_path(r"C:\Windows\notepad.exe"),
            Some(String::from("/windows/c/Windows/notepad.exe")));
    }

    #[test]
    fn rejects_escape_past_a_drive_root() {
        assert_eq!(normalize_path("/windows/c/.."), None);
        assert_eq!(normalize_path("/windows/c/Games/../../etc"), None);
    }

    #[test]
    fn object_name_root_handles_relative_and_absolute_names() {
        assert_eq!(resolve_object_path(Some("/windows/c/Windows"), "System32/notepad.exe"),
            Some(String::from("/windows/c/Windows/System32/notepad.exe")));
        assert_eq!(resolve_object_path(Some("/windows/c/Windows"), r"C:\\Temp\\note.txt"),
            Some(String::from("/windows/c/Temp/note.txt")));
        assert_eq!(resolve_object_path(None, "System32/notepad.exe"), None);
    }

    #[test]
    fn joins_relative_names_to_the_canonical_root() {
        assert_eq!(join_root_path("/windows/c/Games", "data.pak"),
            Some(String::from("/windows/c/Games/data.pak")));
        assert_eq!(join_root_path("/windows/c/Games", "..\\data.pak"),
            Some(String::from("/windows/c/data.pak")));
        assert_eq!(join_root_path("/windows/c", "..\\data.pak"), None);
        assert_eq!(join_root_path("/windows/c/Games", "/absolute"), None);
    }

    #[test]
    fn renders_canonical_drive_paths_for_nt_replies() {
        assert_eq!(render_windows_path("/windows/c/Games/data.pak"), Some(String::from(r"C:\Games\data.pak")));
        assert_eq!(render_windows_path("/windows/d"), Some(String::from(r"D:\")));
    }

    #[test]
    fn renders_canonical_unc_paths_for_nt_replies() {
        assert_eq!(render_windows_path("/windows/unc/server/Share/data.pak"),
            Some(String::from(r"\\server\Share\data.pak")));
    }

    #[test]
    fn renders_non_drive_paths_without_changing_root() {
        assert_eq!(render_windows_path("/Device/Null"), Some(String::from(r"\Device\Null")));
    }

    #[test]
    fn utf16_boundaries_accept_pairs_and_reject_unpaired_surrogates() {
        assert_eq!(super::decode_utf16(&[0xd83d, 0xde00]).as_deref(), Some("😀"));
        assert_eq!(super::decode_utf16(&[0xd83d]), None);
        assert_eq!(super::decode_utf16(&[0xde00]), None);
        assert_eq!(super::decode_utf16(&[b'A' as u16, 0xd83d, b'B' as u16]), None);
    }
}
