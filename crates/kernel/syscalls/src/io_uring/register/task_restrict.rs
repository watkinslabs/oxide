// `IORING_REGISTER_RESTRICTIONS` with no ring: the calling task restricts
// ITSELF.
//
// The ring form (`register::rings::restrictions`) confines one ring, and only
// while that ring is still disabled — which is enough for a process that
// builds a ring and hands it to less-trusted code, and useless against code
// that simply opens a ring of its own. The task form closes that: the
// allow-list is recorded on the task, inherited across `fork`, and folded into
// every ring the task creates from then on, so there is no fresh ring to
// escape through.
//
// The permission rule is seccomp's, for seccomp's reason: a task that can
// still gain privilege through `execve` must not be able to install a
// confinement a later, more privileged image would inherit.

use alloc::vec::Vec;

use syscall::errno::Errno;

use sched::task::io_uring::IouRestrictReg;

use crate::io_uring_abi::restriction::{admit_task_header, decode_one, Restrictions,
                                       IORING_MAX_RESTRICTIONS, RESTRICTION_BYTES,
                                       TASK_RESTRICTION_HDR};

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Read the rule array following the record header. # C: O(nr)
fn read_rules(arg: u64, nr: u32) -> Result<Vec<IouRestrictReg>, Errno> {
    if nr > IORING_MAX_RESTRICTIONS { return Err(Errno::Einval); }
    let mut out: Vec<IouRestrictReg> = Vec::new();
    out.try_reserve_exact(nr as usize).map_err(|_| Errno::Enomem)?;
    for i in 0..nr as u64 {
        let mut b = [0u8; RESTRICTION_BYTES as usize];
        let at = TASK_RESTRICTION_HDR
            .checked_add(i.checked_mul(RESTRICTION_BYTES).ok_or(Errno::Eoverflow)?)
            .and_then(|off| arg.checked_add(off))
            .ok_or(Errno::Eoverflow)?;
        if uaccess::copy_from_user(&mut b, at).is_err() { return Err(Errno::Efault); }
        let (kind, val) = decode_one(&b).ok_or(Errno::Einval)?;
        out.push(IouRestrictReg { kind, val });
    }
    Ok(out)
}

/// `IORING_REGISTER_RESTRICTIONS`, `fd == -1`.
///
/// The order is the reference's and the order matters: a task that already
/// registered is `EPERM` BEFORE the privilege question is asked, so a
/// privileged task cannot widen its own allow-list by registering twice, and
/// the privilege question is asked before the argument count so an
/// unprivileged caller learns it may not do this at all rather than that it
/// passed the wrong `nr_args`.
///
/// A parse failure stores NOTHING. A half-applied allow-list is the one
/// outcome a confinement must never have. # C: O(nr)
pub fn register_task(arg: u64, nr_args: u32) -> i64 {
    let Some(cur) = sched::live::current() else { return err(Errno::Eacces) };
    if cur.io_uring_restrict.lock().is_some() { return err(Errno::Eperm); }

    use core::sync::atomic::Ordering;
    let nnp = cur.no_new_privs.load(Ordering::Acquire);
    if !nnp && !cur.has_cap(sched::cap::SYS_ADMIN) { return err(Errno::Eacces); }
    if nr_args != 1 { return err(Errno::Einval); }

    let mut hdr = [0u8; TASK_RESTRICTION_HDR as usize];
    if uaccess::copy_from_user(&mut hdr, arg).is_err() { return err(Errno::Efault); }
    let nr = match admit_task_header(&hdr) { Ok(n) => n, Err(e) => return err(e) };

    let rules = match read_rules(arg, nr) { Ok(r) => r, Err(e) => return err(e) };
    // Built once here purely to reject a bad rule before anything is stored:
    // the stored form is the registration, not the derived allow-list, so the
    // fold at ring construction is the only place that meaning lives.
    let pairs: Vec<(u16, u8)> = rules.iter().map(|r| (r.kind, r.val)).collect();
    if let Err(e) = Restrictions::build(&pairs) { return err(e); }

    match cur.io_uring_restrict_set(rules) { Ok(()) => 0, Err(e) => err(e) }
}

/// Build a new ring's restriction state from the allow-list the creating task
/// imposed on itself. A task that registered nothing gets the permissive
/// default; a task that registered an EMPTY list gets a ring that may do
/// nothing, which is why `None` and `Some(empty)` cannot be collapsed.
/// # C: O(N_regs)
pub fn inherited_restrictions() -> Restrictions {
    let Some(cur) = sched::live::current() else { return Restrictions::default() };
    let Some(regs) = cur.io_uring_restrict_snapshot() else { return Restrictions::default() };
    let pairs: Vec<(u16, u8)> = regs.iter().map(|r| (r.kind, r.val)).collect();
    // The rules were validated at registration, so this cannot fail; a
    // permissive default on an impossible error would silently unconfine the
    // ring, so the empty-armed set is the safe answer instead.
    Restrictions::build(&pairs).unwrap_or_else(|_| {
        let mut r = Restrictions::default();
        r.arm_empty();
        r
    })
}
