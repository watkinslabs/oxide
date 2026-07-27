//! `prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, addr, size, name)`.
//!
//! The VMA owner stores the name, preserves it across splits/fork, and emits
//! it through `/proc/<pid>/maps`; this ABI shim only validates and copies the
//! Linux user string before invoking that one owner.

#![cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]

use alloc::sync::Arc;
use alloc::vec::Vec;
use syscall::errno::Errno;
use syscall::SyscallArgs;

use crate::Task;

const PR_SET_VMA_ANON_NAME: u64 = 0;
const ANON_VMA_NAME_MAX_LEN: usize = 80;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

fn read_name(ptr: u64) -> Result<Option<Arc<str>>, i64> {
    if ptr == 0 { return Ok(None); }
    let mut bytes = Vec::new();
    for off in 0..ANON_VMA_NAME_MAX_LEN {
        let mut b = [0u8; 1];
        uaccess::copy_from_user(&mut b, ptr.checked_add(off as u64).ok_or(err(Errno::Efault))?)
            .map_err(|_| err(Errno::Efault))?;
        if b[0] == 0 {
            let valid = bytes.iter().all(|c| *c > 0x1f && *c < 0x7f
                && !matches!(*c, b'\\' | b'`' | b'$' | b'[' | b']'));
            if !valid { return Err(err(Errno::Einval)); }
            let text = core::str::from_utf8(&bytes).map_err(|_| err(Errno::Einval))?;
            return Ok(Some(Arc::from(text)));
        }
        bytes.push(b[0]);
    }
    Err(err(Errno::Enametoolong))
}

/// Linux `PR_SET_VMA_ANON_NAME`: name or clear anonymous VMAs over the page
/// rounded range. Linux accepts only subcommand zero and reports `EBADF` for
/// file-backed mappings, `ENOMEM` for holes, and `EINVAL` for malformed input.
/// # C: O(K log N + name.len())
pub fn sys_set_vma_name(cur: &Task, args: &SyscallArgs) -> i64 {
    if args.a1 != PR_SET_VMA_ANON_NAME { return err(Errno::Einval); }
    let name = match read_name(args.a4) { Ok(v) => v, Err(e) => return e };
    // SAFETY: syscall dispatch runs against the calling task's stable mm.
    let mm = match unsafe { cur.mm_ref() } { Some(m) => m.clone(), None => return err(Errno::Einval) };
    match mm.set_anon_vma_name(args.a2, args.a3, name) {
        Ok(()) => 0,
        Err(vmm::Error::Access) => err(Errno::Ebadf),
        Err(vmm::Error::NoMem) => err(Errno::Enomem),
        Err(_) => err(Errno::Einval),
    }
}
