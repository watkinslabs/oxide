//! Canonical DOS/NT path normalization at the Windows personality boundary.
//!
//! The VFS remains the owner of lookup, permissions, sharing, and file
//! lifetime.  This crate owns only the syntax conversion so every caller uses
//! one drive-letter/backslash/case policy.

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsPath {
    pub drive: u8,
    pub components: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathError { Empty, MissingDrive, InvalidDrive, AbsoluteRequired, EscapeRoot, EmptyComponent }

impl WindowsPath {
    /// Parse an absolute `C:\...` path, accepting `/` as Wine does at the
    /// Unix-facing boundary while emitting only canonical components.
    /// # C: O(path length)
    pub fn parse(path: &str) -> Result<Self, PathError> {
        if path.is_empty() { return Err(PathError::Empty); }
        let bytes = path.as_bytes();
        if bytes.len() < 3 || bytes[1] != b':' { return Err(PathError::MissingDrive); }
        if !bytes[0].is_ascii_alphabetic() { return Err(PathError::InvalidDrive); }
        if bytes[2] != b'\\' && bytes[2] != b'/' { return Err(PathError::AbsoluteRequired); }
        let mut components = Vec::new();
        for raw in path[3..].split(['\\', '/']) {
            if raw.is_empty() { continue; }
            match raw {
                "." => {}
                ".." => { components.pop().ok_or(PathError::EscapeRoot)?; }
                _ if raw.contains(':') => return Err(PathError::InvalidDrive),
                _ => components.push(raw.to_string()),
            }
        }
        Ok(Self { drive: bytes[0].to_ascii_lowercase(), components })
    }

    /// Produce the one host-relative namespace form consumed by the VFS
    /// adapter.  Case is preserved for presentation; lookup folds it.
    /// # C: O(path length)
    pub fn host_path(&self) -> String {
        let mut value = format!("windows/{}/", self.drive as char);
        value.push_str(&self.components.join("/"));
        value
    }

    /// Comparison key for case-insensitive Windows lookup.
    /// # C: O(path length)
    pub fn lookup_key(&self) -> String {
        let mut value = format!("{}:", self.drive as char);
        for component in &self.components {
            value.push('/');
            value.push_str(&component.to_ascii_lowercase());
        }
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalizes_drive_separators_and_dot_segments() {
        let path = WindowsPath::parse(r"C:\Games//Demo\.\bin\..\demo.exe").unwrap();
        assert_eq!(path.drive, b'c');
        assert_eq!(path.components, ["Games", "Demo", "demo.exe"]);
        assert_eq!(path.host_path(), "windows/c/Games/Demo/demo.exe");
        assert_eq!(path.lookup_key(), "c:/games/demo/demo.exe");
    }

    #[test]
    fn lookup_folds_ascii_without_destroying_display_case() {
        let path = WindowsPath::parse(r"d:\Users\Alice\Save.DAT").unwrap();
        assert_eq!(path.host_path(), "windows/d/Users/Alice/Save.DAT");
        assert_eq!(path.lookup_key(), "d:/users/alice/save.dat");
    }

    #[test]
    fn rejects_relative_wrong_drive_and_root_escape() {
        assert_eq!(WindowsPath::parse("notes.txt"), Err(PathError::MissingDrive));
        assert_eq!(WindowsPath::parse(r"C:notes.txt"), Err(PathError::AbsoluteRequired));
        assert_eq!(WindowsPath::parse(r"1:\file"), Err(PathError::InvalidDrive));
        assert_eq!(WindowsPath::parse(r"C:\..\file"), Err(PathError::EscapeRoot));
    }
}
