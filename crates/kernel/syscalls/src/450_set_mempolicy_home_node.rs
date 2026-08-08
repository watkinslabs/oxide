// 450 set_mempolicy_home_node — `SYSCALL_DEFINE4(set_mempolicy_home_node)`
//. ABI shim (docs/53).

#![cfg(target_os = "oxide-kernel")]

use syscall::errno::Errno;
use syscall::SyscallArgs;
use vmm::mempolicy::args::{align_range, home_node_ok};
use vmm::HomeNodeErr;

use crate::misc::mempolicy_common::{current_mm, err, errno_of};

/// `set_mempolicy_home_node(start, len, home_node, flags)`.
///
/// `home_node` is `unsigned long`, so the "clear it" sentinel `-1` arrives as
/// `ULONG_MAX` and fails `home_node >= MAX_NUMNODES` — there is no way to
/// unset a home node, and passing -1 is EINVAL.
///
/// The return is a three-way: ENOENT when no VMA in the range carried a
/// policy at all (Linux seeds `err = -ENOENT` and only a successful
/// `mbind_range` clears it), EOPNOTSUPP when one carried a policy that is
/// neither MPOL_BIND nor MPOL_PREFERRED_MANY, else 0.
/// # C: O(K log N)
pub fn sys_set_mempolicy_home_node(args: &SyscallArgs) -> i64 {
    let (start, len, home_node, flags) = (args.a0, args.a1, args.a2, args.a3);
    if start & (hal::PAGE_SIZE_BYTES - 1) != 0 { return err(Errno::Einval); }
    if flags != 0 { return err(Errno::Einval); }
    if !home_node_ok(home_node) { return err(Errno::Einval); }
    let range = match align_range(start, len) { Ok(r) => r, Err(e) => return errno_of(e) };
    let Some((start, end)) = range else { return 0 };
    let Some(mm) = current_mm() else { return err(Errno::Einval) };
    match mm.set_home_node_range(start, end, home_node as i32) {
        Ok(()) => 0,
        Err(HomeNodeErr::NoEnt) => err(Errno::Enoent),
        Err(HomeNodeErr::OpNotSupp) => err(Errno::Eopnotsupp),
    }
}
