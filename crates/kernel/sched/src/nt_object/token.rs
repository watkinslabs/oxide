//! Snapshot-backed NT primary token.

/// Credentials captured when the NT token object is opened.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NtToken {
    uid: u32,
    gid: u32,
}

impl NtToken {
    pub const fn new(uid: u32, gid: u32) -> Self { Self { uid, gid } }
    pub const fn uid(&self) -> u32 { self.uid }
    pub const fn gid(&self) -> u32 { self.gid }
}
