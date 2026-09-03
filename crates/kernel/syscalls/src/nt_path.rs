//! Windows NT path translation into the kernel VFS namespace.

extern crate alloc;
use alloc::string::String;

/// Translate an absolute DOS/NT path to the Windows VFS root.
///
/// Drive-relative paths such as `C:foo` are deliberately rejected until the
/// runtime has a per-drive current-directory table.  Treating them as
/// `C:\\foo` would silently open a different file than Windows does.
pub fn normalize_path(raw: &str) -> Option<String> {
    if raw.chars().any(|c| c == '\0') { return None; }
    let path = raw
        .strip_prefix("\\??\\")
        .or_else(|| raw.strip_prefix("\\DosDevices\\"))
        .unwrap_or(raw);
    let path = path.replace('\\', "/");
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' {
        if !bytes[0].is_ascii_alphabetic() || bytes.get(2) != Some(&b'/') {
            return None;
        }
        let drive = (bytes[0] as char).to_ascii_lowercase();
        let suffix = lexical_normalize(&path[2..])?;
        let mut translated = String::from("/windows/");
        translated.push(drive);
        if suffix != "/" { translated.push_str(&suffix); }
        else { translated.push('/'); }
        return Some(translated);
    }
    lexical_normalize(&path)
}

/// Render a canonical VFS path in the DOS spelling exposed by NT file
/// information replies.  The `/windows/<drive>/` mount is the single drive
/// mapping owned by this layer; other absolute paths retain their root while
/// adopting Windows separators.
pub fn render_windows_path(path: &str) -> Option<String> {
    if path.as_bytes().contains(&0) { return None; }
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

fn lexical_normalize(path: &str) -> Option<String> {
    let absolute = path.starts_with('/');
    let mut parts: alloc::vec::Vec<&str> = alloc::vec::Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => match parts.last() {
                Some(last) if *last != ".." => { parts.pop(); }
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
    use super::{join_root_path, normalize_path, render_windows_path};

    #[test]
    fn maps_absolute_drive_paths_to_windows_root() {
        assert_eq!(normalize_path(r"C:\Games\Example\data.pak"),
            Some(String::from("/windows/c/Games/Example/data.pak")));
        assert_eq!(normalize_path(r"\??\D:\Temp\note.txt"),
            Some(String::from("/windows/d/Temp/note.txt")));
    }

    #[test]
    fn preserves_non_drive_absolute_paths() {
        assert_eq!(normalize_path(r"\Device\Null"), Some(String::from("/Device/Null")));
        assert_eq!(normalize_path(r"\DosDevices\C:\"),
            Some(String::from("/windows/c/")));
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
        assert_eq!(normalize_path(r"C:\..\..\data.pak"),
            Some(String::from("/windows/c/data.pak")));
        assert_eq!(normalize_path(r"C:\Games\\data.pak"),
            Some(String::from("/windows/c/Games/data.pak")));
    }

    #[test]
    fn rejects_embedded_nul_before_vfs_lookup() {
        assert_eq!(normalize_path("C:\\Games\\bad\0name"), None);
    }

    #[test]
    fn joins_relative_names_to_the_canonical_root() {
        assert_eq!(join_root_path("/windows/c/Games", "data.pak"),
            Some(String::from("/windows/c/Games/data.pak")));
        assert_eq!(join_root_path("/windows/c/Games", "..\\data.pak"),
            Some(String::from("/windows/c/data.pak")));
        assert_eq!(join_root_path("/windows/c/Games", "/absolute"), None);
    }

    #[test]
    fn renders_canonical_drive_paths_for_nt_replies() {
        assert_eq!(render_windows_path("/windows/c/Games/data.pak"), Some(String::from(r"C:\Games\data.pak")));
        assert_eq!(render_windows_path("/windows/d"), Some(String::from(r"D:\")));
    }

    #[test]
    fn renders_non_drive_paths_without_changing_root() {
        assert_eq!(render_windows_path("/Device/Null"), Some(String::from(r"\Device\Null")));
    }
}
