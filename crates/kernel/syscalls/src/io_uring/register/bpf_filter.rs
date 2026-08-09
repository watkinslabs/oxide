// `IORING_REGISTER_BPF_FILTER`: install a classic-BPF filter on a ring's
// submissions, or on the calling task itself.
//
// Two forms, and the difference is who is confined. With a ring fd the filter
// binds to that ring. Without one (`fd == -1`) the filter binds to the TASK,
// and every ring the task later creates starts from the set it built — which
// is what makes the confinement real rather than something a process escapes
// by opening another ring.
//
// The task form carries seccomp's permission rule for the same reason seccomp
// carries it: a task that can still gain privilege through `execve` must not
// be able to install a filter that a later, more privileged image inherits.

use alloc::sync::Arc;
use alloc::vec::Vec;

use syscall::errno::Errno;

use security::seccomp::insn::SockFilter;
use security::seccomp::verifier::{bpf_check_classic, check_cbpf_ctx_filter};

use crate::io_uring::ctx::IoUringInode;
use crate::io_uring_abi::bpf_filter::*;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Copy `len` `struct sock_filter` entries into the packed form the shared
/// interpreter runs. # C: O(len)
fn read_prog(ptr: u64, len: usize) -> Result<Vec<u64>, Errno> {
    let mut prog: Vec<u64> = Vec::new();
    prog.try_reserve_exact(len).map_err(|_| Errno::Enomem)?;
    for i in 0..len {
        let mut b = [0u8; SOCK_FILTER_BYTES as usize];
        let at = ptr.checked_add(i as u64 * SOCK_FILTER_BYTES).ok_or(Errno::Efault)?;
        if uaccess::copy_from_user(&mut b, at).is_err() { return Err(Errno::Efault); }
        prog.push(SockFilter::new(u16::from_le_bytes([b[0], b[1]]), b[2], b[3],
                                  u32::from_le_bytes([b[4], b[5], b[6], b[7]])).encode());
    }
    Ok(prog)
}

/// The registration record, the payload-size negotiation and the program, in
/// the reference's order.
///
/// The size negotiation is the subtle part: the caller is told this kernel's
/// real payload size EVEN WHEN the negotiation fails, so a program built
/// against the wrong size can be rebuilt against the right one. The write-back
/// therefore happens before the refusal is returned.
/// # C: O(filter_len)
fn import(arg: u64) -> Result<(u32, Arc<Vec<u64>>, bool), Errno> {
    let mut b = [0u8; IOU_BPF_BYTES as usize];
    if uaccess::copy_from_user(&mut b, arg).is_err() { return Err(Errno::Efault); }
    let mut r = IouBpf::from_bytes(&b);
    admit_bpf_reg(&r)?;

    let kernel_pdu = pdu_size_for(r.opcode);
    let sized = admit_pdu_size(r.pdu_size, kernel_pdu, r.flags);
    r.pdu_size = kernel_pdu;
    if uaccess::copy_to_user(arg + BPF_FILTER_OFF, &r.filter_bytes()).is_err() {
        return Err(Errno::Efault);
    }
    sized?;

    // Verified with the same pair seccomp installs its filters through, with
    // this record's length as the load bound. A filter this kernel cannot
    // prove safe is never stored, so nothing unverified can reach the
    // interpreter.
    let prog = read_prog(r.filter_ptr, r.filter_len as usize)?;
    bpf_check_classic(&prog)?;
    check_cbpf_ctx_filter(&prog, BPF_CTX_BYTES)?;
    Ok((r.opcode, Arc::new(prog), r.deny_rest()))
}

/// `IORING_REGISTER_BPF_FILTER` against a ring. # C: O(filter_len + OP_LAST)
pub fn register(inode: &Arc<IoUringInode>, arg: u64) -> i64 {
    let (opcode, prog, deny_rest) = match import(arg) { Ok(v) => v, Err(e) => return err(e) };
    inode.reg.lock().bpf.install(opcode, prog, deny_rest);
    0
}

/// The ring-less form: the calling task confines itself.
///
/// `EACCES` unless the task has already given up gaining privilege through
/// `execve`, or holds `CAP_SYS_ADMIN`. Without it any unprivileged task could
/// install a filter that a privileged image it later execs would inherit —
/// the same escape seccomp's identical check closes. The permission is decided
/// BEFORE the argument count, matching the reference's order.
/// # C: O(filter_len)
pub fn register_task(arg: u64, nr_args: u32) -> i64 {
    let Some(cur) = sched::live::current() else { return err(Errno::Eacces) };
    use core::sync::atomic::Ordering;
    let nnp = cur.no_new_privs.load(Ordering::Acquire);
    if !nnp && !cur.has_cap(sched::cap::SYS_ADMIN) { return err(Errno::Eacces); }
    if nr_args != 1 { return err(Errno::Einval); }

    let (opcode, prog, deny_rest) = match import(arg) { Ok(v) => v, Err(e) => return err(e) };
    match cur.io_uring_filter_push(sched::task::io_uring::IouFilterReg { opcode, deny_rest, prog }) {
        Ok(()) => 0,
        Err(e) => err(e),
    }
}

/// Build a new ring's filter set from the filters the creating task imposed on
/// itself, by replaying its registrations in order.
///
/// Replayed rather than copied: `IO_URING_BPF_FILTER_DENY_REST` acts on the
/// opcodes that had no filter AT THAT MOMENT, so the set is a function of the
/// order the registrations were made in. Reconstructing it from the order is
/// the only thing that reproduces it exactly. # C: O(N_regs x OP_LAST)
pub fn inherited_filters() -> FilterSet {
    let mut set = FilterSet::new();
    let Some(cur) = sched::live::current() else { return set };
    let Some(regs) = cur.io_uring_filters_snapshot() else { return set };
    for r in regs { set.install(r.opcode, r.prog, r.deny_rest); }
    set
}
