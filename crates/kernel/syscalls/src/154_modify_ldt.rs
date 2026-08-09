// 154 modify_ldt — one syscall, one file (docs/53 §0). ABI shim only: the
// sub-function table, the `user_desc` decode, the descriptor packing and the
// whole EINVAL ladder live in the hosted-testable `ldt_abi` module; the table
// itself lives on the address space (`vmm::ldt`) and LDTR programming lives in
// `sched::ldt`. This file parses, copies, calls one work fn and encodes.
//
// x86_64 only. The generic syscall table has no `modify_ldt` number, and no
// aarch64 number translates onto slot 154 — pinned by a test in the arm ABI
// crate — so an arm caller reaches the dispatcher's ENOSYS rather than falling
// through into a descriptor install.
#![cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::ldt_abi::{self, LdtFunc, ReadPlan, UserDesc, USER_DESC_BYTES};

/// Chunk used to zero-fill the caller's buffer past the live table. Sized to
/// stay off the kernel stack's growth path while keeping the fill loop short;
/// the largest fill is the full 64 KiB table.
const ZERO_CHUNK: usize = 256;

/// `clear_user(ptr, len)` — the reference's zero fill, expressed with the
/// copy-out primitive this port has.
fn clear_user(mut ptr: u64, mut len: u64) -> Result<(), Errno> {
    let zeros = [0u8; ZERO_CHUNK];
    while len != 0 {
        let n = (len as usize).min(ZERO_CHUNK);
        uaccess::copy_to_user(ptr, &zeros[..n])?;
        ptr += n as u64;
        len -= n as u64;
    }
    Ok(())
}

/// Execute a `ReadPlan` against `src`, which already holds exactly
/// `plan.copy` bytes of live descriptors.
fn copy_out(ptr: u64, plan: ReadPlan, src: &[u8]) -> i64 {
    if plan.copy != 0 {
        if let Err(e) = uaccess::copy_to_user(ptr, src) { return -(e.as_i32() as i64); }
    }
    if plan.zero != 0 {
        if let Err(e) = clear_user(ptr + plan.copy, plan.zero) { return -(e.as_i32() as i64); }
    }
    plan.retval()
}

/// `modify_ldt(func, ptr, bytecount)` — slot 154.
///
/// The four sub-functions and their argument rules are the reference's; the
/// only thing decided here is which of them runs and where the bytes come
/// from. Everything a caller can get wrong is answered by `ldt_abi`, which is
/// unit-tested; everything the hardware can get wrong is answered by
/// `sched::ldt`, which programs LDTR.
/// # C: O(bytecount) for a read, O(1) for a write
pub fn kernel_modify_ldt(args: &SyscallArgs) -> i64 {
    let ptr = args.a1;
    let bytecount = args.a2;
    let Some(func) = ldt_abi::classify(args.a0 as u32 as i32) else {
        return ldt_abi::unsupported_func_errno();
    };
    match func {
        // The "default LDT" answer needs no address space at all.
        LdtFunc::ReadDefault => return copy_out(ptr, ldt_abi::read::plan_read_default(bytecount), &[]),
        _ => {}
    }
    let Some(cur) = sched::live::current() else { return -(Errno::Efault.as_i32() as i64) };
    // SAFETY: running task, no concurrent mm writer per `13§5`.
    let Some(mm) = (unsafe { cur.mm_ref() }).cloned() else {
        return -(Errno::Efault.as_i32() as i64);
    };
    match func {
        LdtFunc::Read => read_ldt(&mm, ptr, bytecount),
        LdtFunc::Write | LdtFunc::WriteNew => write_ldt(&mm, ptr, bytecount, func),
        // Answered above, before the address space was fetched.
        LdtFunc::ReadDefault => ldt_abi::unsupported_func_errno(),
    }
}

/// `modify_ldt(0, ptr, bytecount)`.
fn read_ldt(mm: &vmm::AddressSpace, ptr: u64, bytecount: u64) -> i64 {
    let plan = ldt_abi::read::plan_read(mm.ldt().nr_entries(), bytecount);
    if plan.copy == 0 { return copy_out(ptr, plan, &[]); }
    // Snapshot under the table lock, then copy out with no lock held: the
    // copy can take a page fault on the caller's buffer, which may sleep.
    let mut buf = alloc::vec::Vec::new();
    if buf.try_reserve_exact(plan.copy as usize).is_err() {
        return -(Errno::Enomem.as_i32() as i64);
    }
    buf.resize(plan.copy as usize, 0u8);
    mm.ldt().read_bytes(&mut buf);
    copy_out(ptr, plan, &buf)
}

/// `modify_ldt(1, …)` and `modify_ldt(0x11, …)`.
fn write_ldt(mm: &vmm::AddressSpace, ptr: u64, bytecount: u64, func: LdtFunc) -> i64 {
    // Size first, pointer second: a wrong `bytecount` is EINVAL whether or not
    // the pointer happens to be mapped.
    if let Err(e) = ldt_abi::write::check_bytecount(bytecount) { return -(e.as_i32() as i64); }
    let mut raw = [0u8; USER_DESC_BYTES as usize];
    if let Err(e) = uaccess::copy_from_user(&mut raw, ptr) { return -(e.as_i32() as i64); }
    let info = UserDesc::decode(&raw);
    let entry = match ldt_abi::validate_write(&info, func) {
        Ok(e) => e,
        Err(e) => return -(e.as_i32() as i64),
    };
    // Grow-and-swap the table, reload LDTR on this CPU and on every CPU
    // running this mm, and only then free the displaced table — one work fn,
    // because the ORDER of those three steps is the safety property.
    if let Err(e) = sched::ldt::install_entry(mm, entry.entry_number, entry.desc) {
        return match e {
            vmm::LdtError::NoMem => -(Errno::Enomem.as_i32() as i64),
            vmm::LdtError::Range => -(Errno::Einval.as_i32() as i64),
        };
    }
    0
}
