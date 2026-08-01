// Mount-data string → `Ext4MountOpts`. Tokeniser + the quota option table +
// the journalled-quota-file name rules. No superblock state is consulted
// here; every check that needs the mounted filesystem lives in
// `consistency.rs`.

use alloc::string::{String, ToString};
use vfs::{KResult, VfsError};

use super::ctx::Ext4MountOpts;
use super::flags::*;

/// Quota classes that have a journalled-quota-file mount option.
const JQUOTA_OPTS: [(&str, vfs::QuotaType); 2] =
    [(OPT_USRJQUOTA, vfs::QuotaType::User), (OPT_GRPJQUOTA, vfs::QuotaType::Group)];

impl Ext4MountOpts {
    /// Parse one comma-separated mount-data string.
    ///
    /// Quota tokens are fully validated: a flag option given a value, a
    /// value option given none, an unknown `jqfmt=` name, and a quota file
    /// name outside the filesystem root are all `EINVAL`. Non-quota tokens
    /// are collected verbatim and never fail the mount.
    /// # C: O(len(data))
    pub fn parse(data: &str) -> KResult<Self> {
        let mut o = Self::default();
        for tok in data.split(OPT_SEP) {
            if tok.is_empty() { continue; }
            let (key, val) = match tok.find(OPT_ASSIGN) {
                Some(i) => (&tok[..i], Some(&tok[i + OPT_ASSIGN.len_utf8()..])),
                None => (tok, None),
            };
            if !o.parse_one(key, val)? { o.other.push(tok.to_string()); }
        }
        Ok(o)
    }

    /// Consume one token. `Ok(false)` = not a quota option. # C: O(len(tok))
    fn parse_one(&mut self, key: &str, val: Option<&str>) -> KResult<bool> {
        let flag_bits = match key {
            OPT_QUOTA | OPT_USRQUOTA => Some(EXT4_MOUNT_QUOTA | EXT4_MOUNT_USRQUOTA),
            OPT_GRPQUOTA => Some(EXT4_MOUNT_QUOTA | EXT4_MOUNT_GRPQUOTA),
            OPT_PRJQUOTA => Some(EXT4_MOUNT_QUOTA | EXT4_MOUNT_PRJQUOTA),
            _ => None,
        };
        if let Some(bits) = flag_bits {
            // A flag option carrying a value is rejected, not ignored.
            if val.is_some() { return Err(VfsError::Einval); }
            self.set_opt(bits);
            return Ok(true);
        }
        if key == OPT_NOQUOTA {
            if val.is_some() { return Err(VfsError::Einval); }
            self.clear_opt(EXT4_MOUNT_QUOTA_MASK);
            return Ok(true);
        }
        for (name, kind) in JQUOTA_OPTS {
            if key != name { continue; }
            let v = val.ok_or(VfsError::Einval)?;
            self.note_qf_name(kind, v)?;
            return Ok(true);
        }
        if key == OPT_JQFMT {
            let v = val.ok_or(VfsError::Einval)?;
            self.jquota_fmt = jqfmt_from_name(v).ok_or(VfsError::Einval)?;
            self.spec_jqfmt = true;
            return Ok(true);
        }
        Ok(false)
    }

    /// Record (or, for an empty name, un-record) a journalled quota file.
    /// Naming the same file twice is accepted; naming a different one is not.
    /// # C: O(len(name))
    pub fn note_qf_name(&mut self, kind: vfs::QuotaType, name: &str) -> KResult<()> {
        let slot = kind.slot();
        self.qname_spec |= 1 << slot;
        self.spec_jquota = true;
        if name.is_empty() {
            self.qf_names[slot] = None;
            return Ok(());
        }
        if name.contains(PATH_SEP) { return Err(VfsError::Einval); }
        match &self.qf_names[slot] {
            Some(prev) if prev != name => Err(VfsError::Einval),
            Some(_) => Ok(()),
            None => { self.qf_names[slot] = Some(String::from(name)); Ok(()) }
        }
    }

    /// Reject mixing the old (`usrquota`) and new (`usrjquota=`) quota forms
    /// within ONE data string, before any superblock state is consulted.
    /// A class named by a quota file drops its plain-quota bit; a plain-quota
    /// bit left standing alongside any quota file name is `EINVAL`.
    /// # C: O(1)
    pub fn validate(&mut self) -> KResult<()> {
        let usr = self.qf_name(vfs::QuotaType::User.slot()).is_some();
        let grp = self.qf_name(vfs::QuotaType::Group.slot()).is_some();
        if !usr && !grp { return Ok(()); }
        // Clear only a bit that is actually SET: touching `mask` for a bit the
        // data string never mentioned would make a later quota-loaded remount
        // read this as an attempted quota-option change.
        if usr && self.test_opt(EXT4_MOUNT_USRQUOTA) { self.clear_opt(EXT4_MOUNT_USRQUOTA); }
        if grp && self.test_opt(EXT4_MOUNT_GRPQUOTA) { self.clear_opt(EXT4_MOUNT_GRPQUOTA); }
        if self.test_opt(EXT4_MOUNT_USRQUOTA) || self.test_opt(EXT4_MOUNT_GRPQUOTA) {
            return Err(VfsError::Einval);
        }
        Ok(())
    }
}
