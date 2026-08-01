// 444 landlock_create_ruleset — one syscall, one file (docs/53 §0). Parse,
// validate through `landlock::abi`, build, encode. No policy here.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use ::landlock::abi::{self, CreateIntent, RulesetAttr};
use ::landlock::uapi::*;
use ::landlock::Ruleset;
use vfs::{File, InodeRef, OpenFlags};

use crate::landlock::make_landlock_inode;

/// `sys_landlock_create_ruleset(attr, size, flags)` — slot 444.
///
/// With a flag set this is a query, not a constructor: it reports the supported
/// ABI version or the errata bitmask. Programs feature-detect through the
/// version query and disable their sandbox entirely if it fails, so the query
/// path is answered before anything touches user memory.
/// # C: O(1)
pub fn sys_landlock_create_ruleset(args: &SyscallArgs) -> i64 {
    let attr  = args.a0;
    let size  = args.a1 as usize;
    let flags = args.a2 as u32;

    match abi::create_intent(attr, size, flags) {
        Err(e) => return -(e.as_i32() as i64),
        Ok(CreateIntent::Version) => return ABI_VERSION,
        Ok(CreateIntent::Errata)  => return ERRATA,
        Ok(CreateIntent::Ruleset) => {}
    }

    if let Err(e) = abi::attr_buffer_ok(attr, size, RULESET_ATTR_MIN_SIZE) {
        return -(e.as_i32() as i64);
    }

    // Members past the caller's size read as zero, so a program built against
    // an older header gets exactly the policy it asked for. Bytes past the
    // members this kernel knows must be zero: a non-zero one means the caller
    // is asking for something that would silently not be enforced.
    let mut buf = [0u8; RULESET_ATTR_SIZE];
    let head = core::cmp::min(size, RULESET_ATTR_SIZE);
    if uaccess::copy_from_user(&mut buf[..head], attr).is_err() {
        return -(Errno::Efault.as_i32() as i64);
    }
    if size > RULESET_ATTR_SIZE {
        match tail_is_zero(attr + RULESET_ATTR_SIZE as u64, size - RULESET_ATTR_SIZE) {
            Err(e) => return -(e.as_i32() as i64),
            Ok(false) => return -(Errno::E2big.as_i32() as i64),
            Ok(true) => {}
        }
    }

    let a = RulesetAttr::decode(&buf);
    if let Err(e) = a.validate() { return -(e.as_i32() as i64); }

    let rs = Ruleset::new(&a);
    let inode: InodeRef = make_landlock_inode(rs);
    let dentry = vfs::dcache::d_alloc_pseudo("[landlock-ruleset]", inode.clone(),
                                             &crate::anon_dname::ANON_INODE_OPS);
    // Read/write so both `landlock_add_rule` and `landlock_restrict_self`
    // accept it, and close-on-exec so a ruleset under construction does not
    // leak into an unrelated program.
    let file = File::new(inode, dentry, OpenFlags::O_RDWR);
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole writer of its own fd table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    match fdt.alloc_limit(file, cur.nofile_soft()) {
        Ok(fd) => { let _ = fdt.set_cloexec(fd, true); fd as i64 }
        Err(e) => -(e as i64),
    }
}

/// Whether every byte of a user-supplied attr tail is zero.
/// # C: O(N_bytes)
fn tail_is_zero(mut addr: u64, mut len: usize) -> Result<bool, Errno> {
    let mut chunk = [0u8; 64];
    while len > 0 {
        let n = core::cmp::min(len, chunk.len());
        if uaccess::copy_from_user(&mut chunk[..n], addr).is_err() { return Err(Errno::Efault); }
        if chunk[..n].iter().any(|b| *b != 0) { return Ok(false); }
        addr += n as u64;
        len -= n;
    }
    Ok(true)
}
