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
    /// Return the stable NT SID derived from this token's Unix identity. # C: O(1)
    pub fn user_sid(&self) -> [u8; 16] { sid(5, self.uid) }
    /// Snapshot token group membership for serialization or policy. # C: O(groups)
    pub fn groups(&self) -> Vec<NtTokenGroup> { self.groups.lock().clone() }
    /// Add one privilege while assembling a freshly opened token. # C: O(1)
    pub fn add_privilege(&self, privilege: NtTokenPrivilege) { self.privileges.lock().push(privilege); }
    /// Serialize variable-length Windows token records with inline SIDs.
    /// # C: O(groups + privileges)
    pub fn query_bytes(&self, class: u32, base: u64) -> Option<Vec<u8>> {
        const TOKEN_USER: u32 = 1;
        const TOKEN_GROUPS: u32 = 2;
        const TOKEN_PRIVILEGES: u32 = 3;
        let mut bytes = Vec::new();
        match class {
            TOKEN_USER => {
                bytes.resize(32, 0);
                bytes[0..8].copy_from_slice(&base.checked_add(16)?.to_ne_bytes());
                bytes[16..32].copy_from_slice(&self.user_sid());
            }
            TOKEN_GROUPS => {
                let groups = self.groups();
                bytes = Self::groups_bytes(&groups, base)?;
            }
            TOKEN_PRIVILEGES => {
                let privileges = self.privileges();
                bytes.resize(8usize.checked_add(privileges.len().checked_mul(16)?)?, 0);
                bytes[0..4].copy_from_slice(&(privileges.len() as u32).to_ne_bytes());
                for (index, privilege) in privileges.iter().enumerate() {
                    let entry = 8 + index * 16;
                    bytes[entry..entry + 8].copy_from_slice(&privilege.luid.to_ne_bytes());
                    bytes[entry + 8..entry + 12].copy_from_slice(&privilege.attributes.to_ne_bytes());
                }
            }
            _ => return None,
        }
        Some(bytes)
    }
    /// Serialize a TOKEN_GROUPS record with inline SIDs at `base`. # C: O(groups)
    pub fn groups_bytes(groups: &[NtTokenGroup], base: u64) -> Option<Vec<u8>> {
        let sid_base = 8usize.checked_add(groups.len().checked_mul(16)?)?;
        let mut bytes = Vec::new();
        bytes.resize(sid_base.checked_add(groups.len().checked_mul(16)?)?, 0);
        bytes[0..4].copy_from_slice(&(groups.len() as u32).to_ne_bytes());
        for (index, group) in groups.iter().enumerate() {
            let entry = 8 + index * 16;
            let sid_offset = sid_base + index * 16;
            bytes[entry..entry + 8].copy_from_slice(&base.checked_add(sid_offset as u64)?.to_ne_bytes());
            bytes[entry + 8..entry + 12].copy_from_slice(&group.attributes.to_ne_bytes());
            bytes[sid_offset..sid_offset + 16].copy_from_slice(&group.sid);
        }
        Some(bytes)
    }
    /// Replace or reset NT group state and return the state replaced. # C: O(groups)
    pub fn adjust_groups(&self, reset_to_default: bool, groups: Vec<NtTokenGroup>) -> Vec<NtTokenGroup> {
        let mut current = self.groups.lock();
        let previous = current.clone();
        *current = if reset_to_default { alloc::vec![NtTokenGroup { sid: sid(5, self.gid), attributes: 4 }] } else { groups };
        previous
    }
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

/// Encode one Unix identity as a valid NT authority SID. # C: O(1)
pub fn sid_for_id(subauthority: u32) -> [u8; 16] {
    sid(5, subauthority)
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

    #[test]
    fn query_records_use_inline_sids_and_windows_x64_alignment() {
        let token = NtToken::new(1000, 1001);
        let user = token.query_bytes(1, 0x1000).unwrap();
        assert_eq!(user.len(), 32);
        assert_eq!(u64::from_ne_bytes(user[..8].try_into().unwrap()), 0x1010);
        assert_eq!(&user[16..], &token.user_sid());
        let groups = token.query_bytes(2, 0x2000).unwrap();
        assert_eq!(u32::from_ne_bytes(groups[..4].try_into().unwrap()), 1);
        assert_eq!(u64::from_ne_bytes(groups[8..16].try_into().unwrap()), 0x2018);
        assert_eq!(groups.len(), 40);
    }

    #[test]
    fn query_privileges_contains_change_notify() {
        let token = NtToken::new(1000, 1001);
        token.add_privilege(NtTokenPrivilege { luid: 23, attributes: 3 });
        let bytes = token.query_bytes(3, 0x3000).unwrap();
        assert_eq!(u32::from_ne_bytes(bytes[..4].try_into().unwrap()), 1);
        assert_eq!(u64::from_ne_bytes(bytes[8..16].try_into().unwrap()), 23);
        assert_eq!(u32::from_ne_bytes(bytes[16..20].try_into().unwrap()), 3);
    }

    #[test]
    fn adjust_groups_returns_replaced_state_and_packs_previous_groups() {
        let token = NtToken::new(1000, 1001);
        let replacement = sid(5, 2000);
        token.replace_groups(vec![NtTokenGroup { sid: replacement, attributes: 4 }]);

        let previous = token.adjust_groups(false, vec![NtTokenGroup { sid: sid(5, 3000), attributes: 4 }]);
        let bytes = NtToken::groups_bytes(&previous, 0x4000).unwrap();

        assert_eq!(previous.len(), 1);
        assert_eq!(u32::from_ne_bytes(bytes[0..4].try_into().unwrap()), 1);
        assert_eq!(u64::from_ne_bytes(bytes[8..16].try_into().unwrap()), 0x4018);
        assert_eq!(&bytes[24..40], &replacement);
        assert!(token.has_sid(&sid(5, 3000)));
        assert!(!token.has_sid(&replacement));
    }

    #[test]
    fn reset_groups_restores_the_token_gid_group() {
        let token = NtToken::new(1000, 1001);
        token.replace_groups(vec![NtTokenGroup { sid: sid(5, 3000), attributes: 4 }]);

        let previous = token.adjust_groups(true, alloc::vec::Vec::new());

        assert_eq!(previous[0].sid, sid(5, 3000));
        assert!(token.has_sid(&sid(5, 1001)));
        assert!(!token.has_sid(&sid(5, 3000)));
    }
}
