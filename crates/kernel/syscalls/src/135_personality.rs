// 135 personality — one syscall, one file (docs/53 §0). ABI shim only; the
// persona store + query rule live in `sched::personality::get_set`.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_personality(persona)` — slot 135. Returns the PREVIOUS persona and, for
/// any argument other than `PERSONALITY_QUERY` (0xffffffff), installs the new
/// one. The return is an `unsigned int` widened to long, never an errno: the
/// UAPI reserves the top bit of the domain byte so a persona can't alias `-E*`.
/// # C: O(1)
pub fn sys_personality(args: &SyscallArgs) -> i64 {
    let cur = match sched::live::current() { Some(cur) => cur, None => return 0 };
    sched::personality::get_set(cur, args.a0 as u32) as i64
}
