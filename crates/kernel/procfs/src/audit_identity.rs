// `/proc/<pid>/{loginuid,sessionid}` over the task's canonical audit identity.

#[cfg(target_os = "oxide-kernel")]
use alloc::sync::Arc;
use alloc::vec::Vec;

use namespace_identity::NamespaceRef;
use user_namespace::IdMapKind;
use vfs::{FileCred, KResult, VfsError};
#[cfg(target_os = "oxide-kernel")]
use vfs::{mk_mode, File, FileOps, FileType, Inode, InodeBuilder, InodeOps, InodeRef};

const LOGINUID_TAG: u64 = 0x4b;
const SESSIONID_TAG: u64 = 0x4c;
const FILE_MODE: u16 = 0o644;

#[derive(Copy, Clone)]
enum Kind { LoginUid, SessionId }

struct AuditIdentityFile { tid: u32, kind: Kind }

fn dec(mut n: u32) -> Vec<u8> {
    if n == 0 { return alloc::vec![b'0']; }
    let mut rev = [0u8; 10];
    let mut len = 0;
    while n != 0 { rev[len] = b'0' + (n % 10) as u8; n /= 10; len += 1; }
    let mut out = Vec::with_capacity(len);
    while len != 0 { len -= 1; out.push(rev[len]); }
    out
}

fn login_for(owner: &NamespaceRef, login: u32) -> u32 {
    if login == audit::login::UNSET { return login; }
    match user_namespace::is_mapped(owner, IdMapKind::Uid, login) {
        Ok(true) => user_namespace::resolve_to_ns(owner, IdMapKind::Uid, login)
            .unwrap_or(audit::login::UNSET),
        _ => audit::login::UNSET,
    }
}

fn body(task: &sched::Task, owner: &NamespaceRef, kind: Kind) -> Vec<u8> {
    let (login, session) = task.audit_identity();
    dec(match kind { Kind::LoginUid => login_for(owner, login), Kind::SessionId => session })
}

fn parse(src: &[u8]) -> KResult<u32> {
    let text = core::str::from_utf8(src).map_err(|_| VfsError::Einval)?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    if text.is_empty() || text.contains('\n') { return Err(VfsError::Einval); }
    let text = text.strip_prefix('+').unwrap_or(text);
    if text.is_empty() { return Err(VfsError::Einval); }
    text.parse::<u32>().map_err(|e| match e.kind() {
        core::num::IntErrorKind::PosOverflow => VfsError::Erange,
        _ => VfsError::Einval,
    })
}

fn apply_with<F>(target: &sched::Task, current: &sched::Task, opener: &FileCred,
                 off: u64, src: &[u8], set: F) -> KResult<usize>
where F: FnOnce(u32, u32) -> Result<u32, syscall::errno::Errno>
{
    if current.kernel_thread.load(core::sync::atomic::Ordering::Acquire) {
        return Err(VfsError::Eperm);
    }
    if current.tid != target.tid { return Err(VfsError::Eperm); }
    if off != 0 { return Err(VfsError::Einval); }
    let visible = parse(src)?;
    let login = if visible == audit::login::UNSET { visible } else {
        user_namespace::resolve_to_host(opener.user_namespace(), IdMapKind::Uid, visible)
            .map_err(|_| VfsError::Einval)?.ok_or(VfsError::Einval)?
    };
    let old = target.audit_identity().0;
    let session = set(old, login).map_err(|e| match e {
        syscall::errno::Errno::Eperm => VfsError::Eperm,
        _ => VfsError::Einval,
    })?;
    target.set_audit_identity(login, session);
    Ok(src.len())
}

#[cfg(target_os = "oxide-kernel")]
fn target(tid: u32) -> KResult<Arc<sched::Task>> {
    sched::live::registry::lookup(tid).ok_or(VfsError::Esrch)
}

#[cfg(target_os = "oxide-kernel")]
struct AuditIdentityOps;

#[cfg(target_os = "oxide-kernel")]
impl InodeOps for AuditIdentityOps {
    fn truncate(&self, _inode: &Inode, _len: u64) -> KResult<()> { Ok(()) }
}

#[cfg(target_os = "oxide-kernel")]
impl FileOps for AuditIdentityOps {
    fn can_poll(&self, _file: &File) -> bool { true }

    fn read_file(&self, file: &File, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let data = file.inode().private::<AuditIdentityFile>().ok_or(VfsError::Einval)?;
        let target = target(data.tid)?;
        let out = body(&target, file.file_cred().user_namespace(), data.kind);
        Ok(crate::dyn_file::read_at(&out, off, buf))
    }

    fn write_file(&self, file: &File, off: u64, src: &[u8]) -> KResult<usize> {
        let data = file.inode().private::<AuditIdentityFile>().ok_or(VfsError::Einval)?;
        if !matches!(data.kind, Kind::LoginUid) { return Err(VfsError::Ebadf); }
        let target = target(data.tid)?;
        let current = sched::live::current().ok_or(VfsError::Esrch)?;
        apply_with(&target, current, file.file_cred(), off, src, |old, new| {
            audit::login::set(old, new, || current.has_cap(sched::cap::AUDIT_CONTROL))
        })
    }
}

#[cfg(target_os = "oxide-kernel")]
fn make(tid: u32, kind: Kind, tag: u64, mode: u16) -> InodeRef {
    InodeBuilder::new(crate::live::pid_ino(tag, tid), mk_mode(FileType::Regular, mode),
        Arc::new(AuditIdentityOps), Arc::new(AuditIdentityOps))
        .private(Arc::new(AuditIdentityFile { tid, kind })).build()
}

#[cfg(target_os = "oxide-kernel")]
pub fn make_loginuid(tid: u32) -> InodeRef { make(tid, Kind::LoginUid, LOGINUID_TAG, FILE_MODE) }

#[cfg(target_os = "oxide-kernel")]
pub fn make_sessionid(tid: u32) -> InodeRef {
    make(tid, Kind::SessionId, SESSIONID_TAG, crate::pid_file_policy::MODE_RUGO)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sched::{SchedClass, Task};

    fn user(tid: u32) -> Task {
        let mm = vmm::AddressSpace::new(0).unwrap();
        Task::new_user(tid, "login", SchedClass::Normal { weight: 1024 }, mm)
    }

    #[test]
    fn the_live_write_updates_the_same_identity_both_files_render() {
        let task = user(8101);
        let opener = FileCred::root();
        let n = apply_with(&task, &task, &opener, 0, b"1000\n", |old, new| {
            assert_eq!((old, new), (u32::MAX, 1000)); Ok(17)
        }).unwrap();
        assert_eq!(n, 5);
        let ns = namespace_identity::initial(namespace_identity::NamespaceKind::User);
        assert_eq!(body(&task, &ns, Kind::LoginUid), b"1000");
        assert_eq!(body(&task, &ns, Kind::SessionId), b"17");
    }

    #[test]
    fn self_and_kernel_thread_gates_precede_offset_and_parse() {
        let current = user(8102);
        let other = user(8103);
        let opener = FileCred::root();
        assert_eq!(apply_with(&other, &current, &opener, 9, b"bad", |_, _| Ok(1)),
            Err(VfsError::Eperm));
        let kt = Task::new(8104, "k", SchedClass::Normal { weight: 1024 });
        assert_eq!(apply_with(&kt, &kt, &opener, 9, b"bad", |_, _| Ok(1)),
            Err(VfsError::Eperm));
        assert_eq!(apply_with(&current, &current, &opener, 9, b"bad", |_, _| Ok(1)),
            Err(VfsError::Einval));
    }

    #[test]
    fn parse_and_user_namespace_mapping_precede_policy() {
        let task = user(8105);
        let opener = FileCred::root();
        assert_eq!(apply_with(&task, &task, &opener, 0, b"1 2", |_, _| Ok(1)),
            Err(VfsError::Einval));
        assert_eq!(parse(b"4294967296"), Err(VfsError::Erange));
    }

    #[test]
    fn loginuid_crosses_the_openers_user_namespace_once_each_way() {
        use namespace_identity::{allocate, initial, NamespaceKind};
        use user_namespace::{write_map, IdMapExtent};

        let init = initial(NamespaceKind::User);
        let view = allocate(NamespaceKind::User, init.clone(), Some(init.clone())).unwrap();
        write_map(&view, IdMapKind::Uid, true, 0,
            &[IdMapExtent { ns_id: 7, host_id: 100_000, count: 1 }]).unwrap();
        let opener = FileCred::new(vfs::Cred::root(), view.clone(), u64::MAX);
        let task = user(8106);
        apply_with(&task, &task, &opener, 0, b"7", |old, new| {
            assert_eq!((old, new), (u32::MAX, 100_000)); Ok(31)
        }).unwrap();
        assert_eq!(body(&task, &view, Kind::LoginUid), b"7");
        assert_eq!(body(&task, &init, Kind::LoginUid), b"100000");
    }
}
