//! Linux `struct kern_ipc_perm` + `ipcperms()` / `ipc_update_perm()`
//! (`ipc/util.c`). ONE implementation for sem, msg and shm — the permission
//! algebra is a single function in Linux and forking it per object class is
//! how the three surfaces silently diverge.

use core::sync::atomic::{AtomicU32, Ordering};

use super::limits::{IPC_PERM_BITS, S_IRWXUGO};

/// Caller-credential snapshot taken once per syscall, so a long ctl path
/// evaluates one consistent set of ids instead of re-reading `current` under
/// each lock.
#[derive(Clone)]
pub struct IpcCred {
    pub euid: u32,
    pub egid: u32,
    /// Supplementary groups, sorted, sharing the task's allocation — Linux
    /// `group_info`. `in_group_p` binary-searches it.
    pub groups: vfs::GroupList,
    pub cap_ipc_owner: bool,
    pub cap_ipc_lock: bool,
    pub cap_sys_admin: bool,
    pub cap_sys_resource: bool,
}

/// Snapshot the running task's effective ids + IPC-relevant capabilities.
/// With no task installed (early boot, hosted unit test) the snapshot is the
/// all-capable root identity, matching how every other pre-init kernel path
/// here treats "no current".
/// # C: O(1)
pub fn current_ipc_cred() -> IpcCred {
    let mut out = IpcCred {
        euid: 0,
        egid: 0,
        groups: vfs::GroupList::empty(),
        cap_ipc_owner: true,
        cap_ipc_lock: true,
        cap_sys_admin: true,
        cap_sys_resource: true,
    };
    if let Some(t) = sched::current() {
        out.euid = t.creds.euid.load(Ordering::Acquire);
        out.egid = t.creds.egid.load(Ordering::Acquire);
        out.cap_ipc_owner = t.has_cap(sched::cap::IPC_OWNER);
        out.cap_ipc_lock = t.has_cap(sched::cap::IPC_LOCK);
        out.cap_sys_admin = t.has_cap(sched::cap::SYS_ADMIN);
        out.cap_sys_resource = t.has_cap(sched::cap::SYS_RESOURCE);
        out.groups = t.creds.vfs_group_list();
    }
    out
}

/// Linux `in_group_p` — effective gid or any supplementary group. # C: O(log n)
pub fn in_group(cred: &IpcCred, gid: u32) -> bool {
    cred.egid == gid || cred.groups.contains(gid)
}

/// Linux `ipcperms()` over loose fields, so callers whose object stores the
/// ids inline (shm) and callers holding an [`IpcPerm`] (sem, msg) share one
/// body. `flg` is the requested access in `S_IRWXUGO` shape; the low three
/// bits of `(flg>>6)|(flg>>3)|flg` are the demanded r/w/x set.
/// # C: O(log n)
pub fn ipc_permitted_fields(
    mode: u32, uid: u32, gid: u32, cuid: u32, cgid: u32, cred: &IpcCred, flg: i32,
) -> bool {
    let requested = (((flg >> 6) | (flg >> 3) | flg) as u32) & IPC_PERM_BITS;
    let mut granted = mode;
    if cred.euid == cuid || cred.euid == uid { granted >>= 6; }
    else if in_group(cred, cgid) || in_group(cred, gid) { granted >>= 3; }
    (requested & !granted & IPC_PERM_BITS) == 0 || cred.cap_ipc_owner
}

/// Linux `struct kern_ipc_perm`. `uid`/`gid`/`mode` are mutable through
/// `IPC_SET` while other CPUs hold an `Arc` to the owning object, so they are
/// atomics rather than `Arc::get_mut`-gated fields: `get_mut` fails whenever
/// any clone exists, which would turn a legal `IPC_SET` into a spurious error.
pub struct IpcPerm {
    /// `key` supplied at creation (`IPC_PRIVATE` for unkeyed objects).
    pub key: i32,
    /// Full identifier handed to userspace: `(seq << IPCMNI_SHIFT) | idx`.
    pub id: i32,
    /// Sequence number component of `id`, for `ipc_checkid`.
    pub seq: u16,
    pub uid: AtomicU32,
    pub gid: AtomicU32,
    /// Creator ids, fixed for the object's lifetime.
    pub cuid: u32,
    pub cgid: u32,
    /// Low 9 bits are `S_IRWXUGO`; upper bits carry class-private flags.
    pub mode: AtomicU32,
}

impl IpcPerm {
    /// Build the perm block for a freshly created object. `mode` is masked to
    /// `S_IRWXUGO` exactly as `newary`/`newque` do.
    /// # C: O(1)
    pub fn new(key: i32, id: i32, seq: u16, flg: i32, cred: &IpcCred) -> Self {
        Self {
            key, id, seq,
            uid: AtomicU32::new(cred.euid),
            gid: AtomicU32::new(cred.egid),
            cuid: cred.euid,
            cgid: cred.egid,
            mode: AtomicU32::new((flg as u32) & S_IRWXUGO),
        }
    }

    /// # C: O(log n)
    pub fn permitted(&self, cred: &IpcCred, flg: i32) -> bool {
        ipc_permitted_fields(
            self.mode.load(Ordering::Acquire),
            self.uid.load(Ordering::Acquire),
            self.gid.load(Ordering::Acquire),
            self.cuid, self.cgid, cred, flg,
        )
    }

    /// Linux `ipcctl_obtain_check` ownership gate for `IPC_SET` / `IPC_RMID`:
    /// effective uid must equal the owner or creator uid, or the caller needs
    /// `CAP_SYS_ADMIN`. # C: O(1)
    pub fn admin_allowed(&self, cred: &IpcCred) -> bool {
        cred.euid == self.cuid || cred.euid == self.uid.load(Ordering::Acquire) || cred.cap_sys_admin
    }

    /// Linux `ipc_update_perm` — `IPC_SET` installs uid/gid wholesale and
    /// replaces only the `S_IRWXUGO` bits of `mode`, preserving class-private
    /// flags such as `SHM_DEST`. # C: O(1)
    pub fn update(&self, uid: u32, gid: u32, mode: u32) {
        self.uid.store(uid, Ordering::Release);
        self.gid.store(gid, Ordering::Release);
        let cur = self.mode.load(Ordering::Acquire);
        self.mode.store((cur & !S_IRWXUGO) | (mode & S_IRWXUGO), Ordering::Release);
    }
}
