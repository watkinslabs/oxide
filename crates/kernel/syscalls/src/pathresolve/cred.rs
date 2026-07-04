#![cfg(target_os = "oxide-kernel")]

/// Snapshot the running task's credentials into the VFS `Cred` (Linux
/// `current_cred()` subset: fsuid/fsgid + the two DAC-bypass caps).
/// # C: O(1)
pub fn current_cred() -> vfs::Cred {
    cred_for(false)
}

/// Like `current_cred()` but built from the task's REAL uid/gid.
/// # C: O(NGROUPS)
pub fn current_cred_real() -> vfs::Cred {
    cred_for(true)
}

/// # C: O(NGROUPS)
fn cred_for(real: bool) -> vfs::Cred {
    use core::sync::atomic::Ordering;
    let Some(c) = sched::live::current() else { return vfs::Cred::root(); };
    let eff = c.creds.cap_effective.load(Ordering::Acquire);
    let (uid, gid) = if real {
        (c.creds.ruid.load(Ordering::Acquire), c.creds.rgid.load(Ordering::Acquire))
    } else {
        (c.creds.fsuid.load(Ordering::Acquire), c.creds.fsgid.load(Ordering::Acquire))
    };
    let ng = (c.creds.ngroups.load(Ordering::Acquire) as usize).min(vfs::CRED_NGROUPS);
    let mut groups = [0u32; vfs::CRED_NGROUPS];
    // SAFETY: groups slot is single-mutator per `13§5`; the running task on this CPU is the sole writer.
    unsafe {
        let g = &*c.creds.groups.get();
        groups[..ng].copy_from_slice(&g[..ng]);
    }
    let has = |cap: u32| eff & (1u64 << cap) != 0;
    vfs::Cred {
        uid,
        gid,
        cap_dac_override: has(sched::cap::DAC_OVERRIDE),
        cap_dac_read_search: has(sched::cap::DAC_READ_SEARCH),
        cap_fowner: has(sched::cap::FOWNER),
        cap_chown: has(sched::cap::CHOWN),
        cap_fsetid: has(sched::cap::FSETID),
        ngroups: ng as u32,
        groups,
    }
}
