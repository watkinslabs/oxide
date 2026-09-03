//! Snapshot-backed NT primary token with mutable group membership.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use sync::{Spinlock, TaskList as TaskListClass};

/// One Windows SID and its TOKEN_GROUPS attribute mask.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NtTokenGroup {
    pub sid: [u8; 16],
    pub attributes: u32,
}

/// One Windows LUID and privilege attribute mask.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NtTokenPrivilege {
    pub luid: u64,
    pub attributes: u32,
}

/// Credentials captured when the NT token object is opened.
pub struct NtToken {
    uid: u32,
    gid: u32,
    groups: Spinlock<Vec<NtTokenGroup>, TaskListClass>,
    privileges: Spinlock<Vec<NtTokenPrivilege>, TaskListClass>,
    session_id: AtomicU32,
}

impl NtToken {
    pub fn new(uid: u32, gid: u32) -> Self {
        let mut groups = Vec::new();
        groups.push(NtTokenGroup { sid: sid(5, gid), attributes: 4 });
        Self { uid, gid, groups: Spinlock::new(groups), privileges: Spinlock::new(Vec::new()), session_id: AtomicU32::new(0) }
    }
    pub const fn uid(&self) -> u32 { self.uid }
    pub const fn gid(&self) -> u32 { self.gid }
    pub fn replace_groups(&self, groups: Vec<NtTokenGroup>) { *self.groups.lock() = groups; }
    pub fn has_sid(&self, sid: &[u8; 16]) -> bool {
        self.groups.lock().iter().any(|group| group.sid == *sid && group.attributes & 4 != 0)
    }
    pub fn adjust_privileges(&self, disable_all: bool, requested: &[NtTokenPrivilege]) -> (Vec<NtTokenPrivilege>, bool) {
        let mut privileges = self.privileges.lock();
        let previous = privileges.clone();
        let mut all_assigned = true;
        if disable_all {
            for privilege in privileges.iter_mut() { privilege.attributes &= !2; }
        } else {
            for request in requested {
                let Some(current) = privileges.iter_mut().find(|privilege| privilege.luid == request.luid) else {
                    all_assigned = false;
                    continue;
                };
                if request.attributes & 4 != 0 { current.attributes = 0; }
                else { current.attributes = (current.attributes & 1) | (request.attributes & 2); }
            }
        }
        (previous, all_assigned)
    }
    pub fn privileges(&self) -> Vec<NtTokenPrivilege> { self.privileges.lock().clone() }
    /// Clone this token while applying Wine's supported filter operation.
    /// Disabled SIDs are removed and matching privileges are disabled; the
    /// source token remains immutable from the new token's perspective.
    pub fn filtered(&self, disabled_sids: &[[u8; 16]], disabled_privileges: &[NtTokenPrivilege]) -> Self {
        let groups = self.groups.lock().iter().copied()
            .filter(|group| !disabled_sids.iter().any(|sid| *sid == group.sid)).collect();
        let mut privileges = self.privileges.lock().clone();
        for privilege in &mut privileges {
            if disabled_privileges.iter().any(|disabled| disabled.luid == privilege.luid) { privilege.attributes &= !2; }
        }
        Self { uid: self.uid, gid: self.gid, groups: Spinlock::new(groups), privileges: Spinlock::new(privileges), session_id: AtomicU32::new(self.session_id()) }
    }
    pub fn session_id(&self) -> u32 { self.session_id.load(Ordering::Acquire) }
    pub fn set_session_id(&self, value: u32) { self.session_id.store(value, Ordering::Release); }
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
    use super::{sid, NtToken, NtTokenGroup, NtTokenPrivilege};

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

    #[test]
    fn disabling_privileges_preserves_the_previous_state() {
        let token = NtToken::new(1000, 1001);
        let privilege = NtTokenPrivilege { luid: 0x11, attributes: 3 };
        token.privileges.lock().push(privilege);

        let (previous, all_assigned) = token.adjust_privileges(true, &[]);

        assert!(all_assigned);
        assert_eq!(previous, vec![privilege]);
        assert_eq!(token.privileges.lock()[0].attributes, 1);
    }

    #[test]
    fn filtered_token_owns_independent_groups_and_privilege_state() {
        let token = NtToken::new(1000, 1001);
        let group = sid(5, 2000);
        token.replace_groups(vec![NtTokenGroup { sid: group, attributes: 4 }]);
        token.privileges.lock().push(NtTokenPrivilege { luid: 0x22, attributes: 3 });

        let filtered = token.filtered(&[group], &[NtTokenPrivilege { luid: 0x22, attributes: 0 }]);

        assert!(!filtered.has_sid(&group));
        assert_eq!(filtered.privileges()[0].attributes, 1);
        assert!(token.has_sid(&group));
        assert_eq!(token.privileges()[0].attributes, 3);
    }
}
