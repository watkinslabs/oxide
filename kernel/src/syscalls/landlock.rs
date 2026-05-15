// landlock_create_ruleset / landlock_add_rule / landlock_restrict_self
// per Linux landlock(7). Per-task chain stored on Task; namei
// check hook (`security::landlock::chain_permits`) walks the chain
// on every path-based syscall.
//
// `landlock_create_ruleset` allocates a registry entry and returns
// an anonymous fd backed by a `LandlockRulesetInode` carrying the
// ruleset id. `landlock_add_rule` resolves the fd → inode → id,
// then appends a (path, allowed_access) rule. `landlock_restrict
// _self` pushes the id onto the calling task's landlock_chain.

#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;
use alloc::sync::Arc;

use syscall::SyscallArgs;
use syscall::errno::Errno;

use ::security::landlock::{self as ll, Rule};
use vfs::{Dentry, File, FileType, Ino, Inode, InodeRef, KResult, OpenFlags, VfsError};

/// /sys/landlock anonymous-fd inode carrying a ruleset id.
pub struct LandlockRulesetInode {
    pub ruleset_id: u64,
}

impl Inode for LandlockRulesetInode {
    fn ino(&self) -> Ino { 0x4C4E_4400_0000_0000 | self.ruleset_id }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn as_any(&self) -> Option<&dyn core::any::Any> { Some(self) }
    fn lookup(&self, _name: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, _o: u64, _b: &mut [u8]) -> KResult<usize> { Err(VfsError::Eio) }
    fn write(&self, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Eio) }
}

/// `sys_landlock_create_ruleset(attr, size, flags)` — slot 444.
/// `attr` points to `struct landlock_ruleset_attr { __u64 handled_access_fs; }`;
/// `size` is `sizeof(attr)`; `flags` = 0 or LANDLOCK_CREATE_RULESET_VERSION
/// (which asks for the supported ABI version).
/// # C: O(1)
pub fn sys_landlock_create_ruleset(args: &SyscallArgs) -> i64 {
    const LANDLOCK_CREATE_RULESET_VERSION: u64 = 1;
    let attr  = args.a0;
    let size  = args.a1;
    let flags = args.a2;
    if (flags & LANDLOCK_CREATE_RULESET_VERSION) != 0 {
        return 1; // ABI v1.
    }
    if attr == 0 || size < 8 || attr >= hal::USER_VA_END {
        return -(Errno::Einval.as_i32() as i64);
    }
    // SAFETY: attr validated < USER_VA_END; 8-byte read of handled_access_fs from caller's AS.
    let handled = unsafe { core::ptr::read_volatile(attr as *const u64) };
    let id = ll::create_ruleset(handled);
    let inode: InodeRef = Arc::new(LandlockRulesetInode { ruleset_id: id });
    let dentry = Dentry::new(None, alloc::string::String::from("landlock"), inode.clone());
    let file = File::new(inode, dentry, OpenFlags::O_RDONLY);
    let cur = match sched::live::current() { Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64) };
    // SAFETY: running task; preempt-off; sole writer of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    match fdt.alloc(file) {
        Ok(fd) => fd as i64,
        Err(e) => -(e as i64),
    }
}

/// `sys_landlock_add_rule(ruleset_fd, type, rule_attr, flags)` —
/// slot 445. Currently only `rule_type == LANDLOCK_RULE_PATH_BENEATH`
/// (1) is supported; arg is `struct landlock_path_beneath_attr
/// { __u64 allowed_access; __s32 parent_fd; }`.
/// # C: O(1)
pub fn sys_landlock_add_rule(args: &SyscallArgs) -> i64 {
    const LANDLOCK_RULE_PATH_BENEATH: u64 = 1;
    let fd        = args.a0 as i32;
    let rule_type = args.a1;
    let attr      = args.a2;
    if rule_type != LANDLOCK_RULE_PATH_BENEATH {
        return -(Errno::Einval.as_i32() as i64);
    }
    if attr == 0 || attr >= hal::USER_VA_END {
        return -(Errno::Einval.as_i32() as i64);
    }
    // SAFETY: attr validated < USER_VA_END; struct landlock_path_beneath_attr layout: u64 allowed + i32 parent_fd; aligned reads through caller's AS.
    let allowed = unsafe { core::ptr::read_volatile(attr as *const u64) };
    // SAFETY: parent_fd at attr+8 inside the same validated struct landlock_path_beneath_attr; aligned i32 read through caller's AS.
    let parent_fd = unsafe { core::ptr::read_volatile((attr + 8) as *const i32) };
    let cur = match sched::live::current() { Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot per `13§5` single-mutator.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // Resolve ruleset fd.
    let rs_file = match fdt.get(fd) {
        Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    let rs_any = match rs_file.inode().as_any() { Some(a) => a, None => return -(Errno::Einval.as_i32() as i64) };
    let rs_inode = match rs_any.downcast_ref::<LandlockRulesetInode>() {
        Some(r) => r, None => return -(Errno::Einval.as_i32() as i64),
    };
    let ruleset = match ll::lookup(rs_inode.ruleset_id) {
        Some(r) => r, None => return -(Errno::Einval.as_i32() as i64),
    };
    // Resolve parent_fd → path.
    let parent_file = match fdt.get(parent_fd) {
        Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    let path: String = parent_file.dentry().name().into();
    ruleset.add(Rule { path_prefix: path, allowed });
    0
}

/// `sys_landlock_restrict_self(ruleset_fd, flags)` — slot 446.
/// Push the ruleset id onto the caller's landlock_chain so every
/// subsequent path-based syscall consults it. Idempotent: re-
/// pushing the same id is allowed; chain order = registration
/// order.
/// # C: O(1)
pub fn sys_landlock_restrict_self(args: &SyscallArgs) -> i64 {
    let fd = args.a0 as i32;
    let cur = match sched::live::current() { Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot per `13§5` single-mutator.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let file = match fdt.get(fd) { Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64) };
    let any = match file.inode().as_any() { Some(a) => a, None => return -(Errno::Einval.as_i32() as i64) };
    let rs_inode = match any.downcast_ref::<LandlockRulesetInode>() {
        Some(r) => r, None => return -(Errno::Einval.as_i32() as i64),
    };
    if ll::lookup(rs_inode.ruleset_id).is_none() {
        return -(Errno::Einval.as_i32() as i64);
    }
    cur.landlock_chain.lock().push(rs_inode.ruleset_id);
    0
}

/// Check `(path, op)` against the calling task's landlock chain.
/// Returns Ok(()) when every entry in the chain allows the op;
/// Err(-EACCES-as-i64) on first denial. Empty chain = unrestricted.
/// Called from path-based syscalls (openat, unlinkat, …) before
/// the actual VFS work.
/// # C: O(N_chain × N_rules)
pub fn check(path: &str, op: u64) -> Result<(), i64> {
    let cur = match sched::live::current() { Some(c) => c, None => return Ok(()) };
    let chain_ids = cur.landlock_chain.lock().clone();
    if chain_ids.is_empty() { return Ok(()); }
    let chain: alloc::vec::Vec<Arc<ll::Ruleset>> =
        chain_ids.into_iter().filter_map(ll::lookup).collect();
    if ll::chain_permits(&chain, path, op) { Ok(()) }
    else { Err(-(Errno::Eacces.as_i32() as i64)) }
}
