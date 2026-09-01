//! Snapshot-backed NT primary token with mutable group membership.

use alloc::vec::Vec;
use sync::{Spinlock, TaskList as TaskListClass};

/// One Windows SID and its TOKEN_GROUPS attribute mask.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NtTokenGroup {
    pub sid: [u8; 16],
    pub attributes: u32,
}

/// Credentials captured when the NT token object is opened.
pub struct NtToken {
    uid: u32,
    gid: u32,
    groups: Spinlock<Vec<NtTokenGroup>, TaskListClass>,
}

impl NtToken {
    pub fn new(uid: u32, gid: u32) -> Self {
        let mut groups = Vec::new();
        groups.push(NtTokenGroup { sid: sid(5, gid), attributes: 4 });
        Self { uid, gid, groups: Spinlock::new(groups) }
    }
    pub const fn uid(&self) -> u32 { self.uid }
    pub const fn gid(&self) -> u32 { self.gid }
    pub fn replace_groups(&self, groups: Vec<NtTokenGroup>) { *self.groups.lock() = groups; }
    pub fn has_sid(&self, sid: &[u8; 16]) -> bool {
        self.groups.lock().iter().any(|group| group.sid == *sid && group.attributes & 4 != 0)
    }
}

fn sid(authority: u64, subauthority: u32) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[0] = 1; out[1] = 2;
    let authority = authority.to_be_bytes();
    out[2..8].copy_from_slice(&authority[2..]);
    out[8..12].copy_from_slice(&21u32.to_le_bytes());
    out[12..16].copy_from_slice(&subauthority.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use super::{sid, NtToken, NtTokenGroup};

    #[test]
    fn replacing_groups_preserves_credential_snapshot() {
        let token = NtToken::new(1000, 1001);
        let group = sid(5, 2000);

        token.replace_groups(vec![NtTokenGroup { sid: group, attributes: 4 }]);

        assert_eq!(token.uid(), 1000);
        assert_eq!(token.gid(), 1001);
        assert!(token.has_sid(&group));
        assert!(!token.has_sid(&sid(5, 1001)));
    }
}
