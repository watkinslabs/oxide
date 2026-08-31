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
    use super::normalize_path;

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
}
