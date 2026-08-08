// Kernel-side plumbing for Landlock. Every decision lives in the `landlock`
// crate, which is ungated and unit-tested; this file only resolves task and
// descriptor state and hands it over.
//
// The hooks are the whole point: a ruleset that is created, populated and
// enforced but consulted by nothing enforces nothing. Every entry point below
// has at least one caller in a path, open, port or signal syscall.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;

use syscall::errno::Errno;

use ::landlock::access as la;
use ::landlock::uapi::AccessMask;
use ::landlock::{Domain, Ruleset};
use vfs::{FileType, Inode, InodeRef, KResult, VfsError, VfsPath};
use vfs::{InodeBuilder, default_inode_ops, mk_mode};
use vfs::FileOps;

/// `i_private` of a ruleset fd: the layer being built. Holding the ruleset here
/// rather than in a side table is what keeps descriptor lifetime and ruleset
/// lifetime the same fact.
pub struct LandlockRulesetInode {
    pub ruleset: Arc<Ruleset>,
}

/// A ruleset fd is a configuration handle, not a data stream.
/// # C: O(1)
struct LandlockFileOps;
impl FileOps for LandlockFileOps {
    fn read(&self, _inode: &Inode, _o: u64, _b: &mut [u8]) -> KResult<usize> { Err(VfsError::Eio) }
    fn write(&self, _inode: &Inode, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Eio) }
}

/// Anonymous inode backing a ruleset fd.
/// # C: O(1)
pub fn make_landlock_inode(ruleset: Arc<Ruleset>) -> InodeRef {
    let ino = 0x4C4E_4400_0000_0000u64 | (Arc::as_ptr(&ruleset) as u64 & 0xFFFF_FFFF);
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o600), default_inode_ops(),
                      Arc::new(LandlockFileOps))
        .private(Arc::new(LandlockRulesetInode { ruleset }))
        .build()
}

/// Resolve a descriptor to the ruleset it backs. A descriptor that is not a
/// ruleset fd is a descriptor-type error, distinct from a closed one, so a
/// caller can tell "wrong fd" from "no fd".
/// # C: O(1)
pub fn ruleset_from_fd(fd: i32) -> Result<Arc<Ruleset>, Errno> {
    let cur = sched::live::current().ok_or(Errno::Esrch)?;
    // SAFETY: running task on this CPU; preempt-off; sole reader of its own fd table slot.
    let fdt = unsafe { cur.fd_table_ref() }.ok_or(Errno::Ebadf)?.clone();
    let f = fdt.get(fd).map_err(|_| Errno::Ebadf)?;
    let p = f.inode().private::<LandlockRulesetInode>().ok_or(Errno::Ebadfd)?;
    Ok(p.ruleset.clone())
}

/// Whether a descriptor is a ruleset fd. A ruleset fd may not anchor a rule.
/// # C: O(1)
pub fn is_ruleset_file(f: &Arc<vfs::File>) -> bool {
    f.inode().private::<LandlockRulesetInode>().is_some()
}

/// Classify a descriptor offered as a rule's `parent_fd`. The verdict itself
/// is `landlock::abi::rule_target_fd_ok`; this only reads the descriptor.
/// # C: O(1)
pub fn rule_target_fd(f: &Arc<vfs::File>) -> ::landlock::abi::RuleTargetFd {
    let inode = f.inode();
    ::landlock::abi::RuleTargetFd {
        is_ruleset: is_ruleset_file(f),
        has_mount:  f.mnt_id() != 0,
        is_anon:    inode.is_anon_file(),
        sb_nouser:  inode.i_sb().map(|sb| sb.s_flags() & vfs::superblock::SB_NOUSER != 0)
                         .unwrap_or(false),
    }
}

/// The calling thread's enforced domain, or `None` when unconfined.
/// # C: O(1)
pub fn current_domain() -> Option<Arc<Domain>> {
    sched::live::current().and_then(|c| c.landlock_domain.lock().clone())
}

/// Install a deeper domain on the calling thread.
/// # C: O(1)
pub fn set_current_domain(d: Arc<Domain>) -> Result<(), Errno> {
    let cur = sched::live::current().ok_or(Errno::Esrch)?;
    *cur.landlock_domain.lock() = Some(d);
    Ok(())
}

/// Gate a resolved path. `Ok` when unconfined or permitted.
/// # C: O(depth × N_layers × N_rules)
pub fn check(path: &VfsPath, op: AccessMask) -> Result<(), i64> {
    match current_domain() {
        None => Ok(()),
        Some(d) => d.check_fs(path, op).map_err(|e| -(e.as_i32() as i64)),
    }
}

/// Gate a not-yet-created child by its containing directory: creation rights
/// are anchored on the parent, since the child is not an object yet.
/// # C: O(depth × N_layers × N_rules)
pub fn check_parent(parent: &VfsPath, op: AccessMask) -> Result<(), i64> {
    check(parent, op)
}

/// Gate an open and return the rights to record on the resulting description.
/// Callers must store the result with `File::set_landlock_access`, or later
/// truncation and device control will be unrestricted.
/// # C: O(depth × N_layers × N_rules)
pub fn open_decide(path: &VfsPath, open_req: AccessMask, is_device: bool) -> Result<u64, i64> {
    match current_domain() {
        None => Ok(u64::MAX),
        Some(d) => la::open_decide(&d, path, open_req, is_device)
            .map_err(|e| -(e.as_i32() as i64)),
    }
}

/// Gate a reparenting (link or rename).
/// # C: O(depth × N_layers × N_rules)
pub fn check_refer(old_dir: &VfsPath, old: &::landlock::refer::Target,
                   new_dir: &VfsPath, new: Option<&::landlock::refer::Target>,
                   removable: bool, exchange: bool) -> Result<(), i64>
{
    match current_domain() {
        None => Ok(()),
        Some(d) => ::landlock::refer::check(&d, old_dir, old, new_dir, new, removable, exchange)
            .map_err(|e| -(e.as_i32() as i64)),
    }
}

/// Gate a port operation.
/// # C: O(N_layers × N_rules)
pub fn check_net(port: u16, op: AccessMask) -> Result<(), i64> {
    match current_domain() {
        None => Ok(()),
        Some(d) => d.check_net(port, op).map_err(|e| -(e.as_i32() as i64)),
    }
}

/// Whether the calling thread's domain isolates it from `peer` for `scope`.
/// # C: O(N_layers)
pub fn scope_denies(scope: AccessMask, peer: Option<&Arc<Domain>>) -> bool {
    match current_domain() {
        None => false,
        Some(d) => d.scope_denies(scope, peer),
    }
}

/// Transport of an internet socket, for port-rule purposes.
/// # C: O(1)
pub fn sock_proto(sock: &net::sock::InetSocket) -> ::landlock::netcheck::Proto {
    net::landlock_addr::sock_proto(sock)
}

/// Gate a socket operation that names an address, for the running task. The
/// decision itself lives beside the socket layer's other address checks so that
/// `bind`/`connect` here and the datagram send path answer from one place.
/// # C: O(N_layers × N_rules)
pub fn check_socket(proto: ::landlock::netcheck::Proto, op: ::landlock::netcheck::Op,
                    bytes: &[u8], sock_family: u16) -> Result<(), i64>
{
    net::landlock_addr::addr_verdict(current_domain().as_ref(), proto, op, bytes, sock_family)
        .map_err(crate::net_errno::errno_from_neterr)
}

// Resolving a pathname UNIX-domain socket has no entry point here on purpose.
// Deciding it needs the answer to "has anyone bound this address at all", which
// only the AF_UNIX registry holds, so the gate is composed in `net` and both
// call sites — `connect(2)` and a send naming a recipient — use that one. A
// wrapper here would put the not-bound-is-not-a-denial rule in two places.

