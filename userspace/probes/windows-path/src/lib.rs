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
pub enum PathError { Empty, InvalidUtf8, MissingDrive, InvalidDrive, AbsoluteRequired, EscapeRoot, EmptyComponent }

impl WindowsPath {
    /// Parse the byte form crossing the Unix-facing Windows boundary.
    /// # C: O(path length)
    pub fn parse_bytes(path: &[u8]) -> Result<Self, PathError> {
        Self::parse(core::str::from_utf8(path).map_err(|_| PathError::InvalidUtf8)?)
    }

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

    /// Comparison key for Unicode case-insensitive Windows lookup.
    ///
    /// The key is separate from `host_path()` so the VFS adapter can resolve
    /// an existing name without changing the spelling retained for display.
    /// # C: O(path length)
    pub fn lookup_key(&self) -> String {
        let mut value = format!("{}:", self.drive as char);
        for component in &self.components {
            value.push('/');
            value.push_str(&unicode_casefold(component));
        }
        value
    }
}

fn unicode_casefold(value: &str) -> String {
    let encoding = utf8::Encoding::from_charset("utf8")
        .expect("the compiled Unicode table must provide utf8");
    let mut capacity = value.len().saturating_mul(4).saturating_add(4);
    loop {
        let mut folded = vec![0u8; capacity];
        match utf8::casefold_into(&encoding, value.as_bytes(), &mut folded) {
            Ok(length) => return String::from_utf8(folded[..length].to_vec())
                .expect("Unicode casefold output is UTF-8"),
            Err(utf8::FoldError::NoSpace) => capacity = capacity.saturating_mul(2),
            Err(utf8::FoldError::Invalid) => unreachable!("WindowsPath stores valid UTF-8"),
        }
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
    fn lookup_folds_unicode_without_destroying_display_case() {
        let path = WindowsPath::parse("C:\\Données\\Résumé.txt").unwrap();
        assert_eq!(path.host_path(), "windows/c/Données/Résumé.txt");
        assert_eq!(path.lookup_key(), "c:/donne\u{301}es/re\u{301}sume\u{301}.txt");
    }

    #[test]
    fn lookup_uses_full_casefold_and_canonical_decomposition() {
        let stored = WindowsPath::parse("C:\\Straße\\Café.txt").unwrap();
        let query = WindowsPath::parse("c:\\STRASSE\\CAFE\u{301}.TXT").unwrap();
        assert_eq!(stored.lookup_key(), query.lookup_key());
        assert_ne!(stored.host_path(), query.host_path());
        assert_ne!(stored.components[0].to_ascii_lowercase(), "strasse");
    }

    #[test]
    fn malformed_utf8_is_rejected_at_the_byte_boundary() {
        assert_eq!(WindowsPath::parse_bytes(b"C:\\ok\\bad\xff"), Err(PathError::InvalidUtf8));
        assert_eq!(WindowsPath::parse_bytes(b"C:\\bad\xc3"), Err(PathError::InvalidUtf8));
    }

    #[test]
    fn rejects_relative_wrong_drive_and_root_escape() {
        assert_eq!(WindowsPath::parse("notes.txt"), Err(PathError::MissingDrive));
        assert_eq!(WindowsPath::parse(r"C:notes.txt"), Err(PathError::AbsoluteRequired));
        assert_eq!(WindowsPath::parse(r"1:\file"), Err(PathError::InvalidDrive));
        assert_eq!(WindowsPath::parse(r"C:\..\file"), Err(PathError::EscapeRoot));
    }
}
