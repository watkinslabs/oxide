#![cfg(target_os = "oxide-kernel")]

/// Snapshot the running task's credentials into the VFS `Cred` (Linux
/// `current_cred()` subset: fsuid/fsgid + the two DAC-bypass caps).
/// # C: O(1)
pub fn current_cred() -> vfs::Cred {
    sched::cred::current_vfs_cred()
}

/// Retain the running task's complete file-opener credential snapshot.
/// # C: O(1)
pub fn file_cred_for(c: &sched::Task) -> Option<vfs::FileCred> {
    use core::sync::atomic::Ordering;
    let user_namespace = c.namespace_owner(namespace_identity::NamespaceKind::User)?;
    let effective = c.creds.cap_effective.load(Ordering::Acquire);
    Some(vfs::FileCred::new(cred_for_effective(c, false, effective), user_namespace, effective)
        .with_security(c.landlock_domain.lock().clone()))
}

/// Like `current_cred()` but built from the task's REAL uid/gid.
/// # C: O(1)
pub fn current_cred_real() -> vfs::Cred {
    let Some(c) = sched::live::current() else { return vfs::Cred::root(); };
    cred_for(&c, true)
}

/// # C: O(1)
fn cred_for(c: &sched::Task, real: bool) -> vfs::Cred {
    use core::sync::atomic::Ordering;
    let effective = c.creds.cap_effective.load(Ordering::Acquire);
    cred_for_effective(c, real, effective)
}

/// # C: O(1)
fn cred_for_effective(c: &sched::Task, real: bool, effective: u64) -> vfs::Cred {
    use core::sync::atomic::Ordering;
    let permitted = c.creds.cap_permitted.load(Ordering::Acquire);
    let (uid, gid) = if real {
        (c.creds.ruid.load(Ordering::Acquire), c.creds.rgid.load(Ordering::Acquire))
    } else {
        (c.creds.fsuid.load(Ordering::Acquire), c.creds.fsgid.load(Ordering::Acquire))
    };
    let eff = if real {
        // Linux `access_override_creds`: the capability fixup runs
        // ONLY when `SECURE_NO_SETUID_FIXUP` is clear. With the securebit set, a
        // process that deliberately keeps its capabilities across a uid switch
        // keeps them here too, and recomputing from uid silently strips them —
        // which is the whole reason the securebit exists.
        let sb = c.creds.securebits.load(Ordering::Acquire);
        let no_fixup = sb & sched::securebits::mask(sched::securebits::SECURE_NO_SETUID_FIXUP) != 0;
        crate::access_cred::access_override_effective(
            uid, permitted, c.creds.cap_effective.load(Ordering::Acquire), no_fixup)
    } else {
        effective
    };
    c.creds.to_vfs_cred(uid, gid, eff)
}
