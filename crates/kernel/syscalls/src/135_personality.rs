// 135 personality — one syscall, one file (docs/53 §0). ABI shim only; the
// persona store, the query rule and the domain gate live in
// `sched::personality`.
#![cfg(target_os = "oxide-kernel")]

use syscall::errno::Errno;
use syscall::SyscallArgs;

/// Whether this arch supplies its own `personality(2)` that validates the
/// execution-domain byte. arm64 does (`SYSCALL_DEFINE1(arm64_personality)`);
/// x86_64 takes the generic entry, which validates nothing.
const ARCH_GATES_DOMAIN: bool = cfg!(target_arch = "aarch64");

/// `sys_personality(persona)` — slot 135. Returns the PREVIOUS persona and, for
/// any argument other than `PERSONALITY_QUERY` (0xffffffff), installs the new
/// one.
///
/// The return is an `unsigned int` ZERO-EXTENDED to long, never an errno: the
/// UAPI reserves the top bit of the domain byte precisely so a persona cannot
/// alias `-E*`, and widening `0xffffffff` as unsigned keeps it `4294967295`
/// rather than `-1`. Sign-extending here would make a query of a persona with
/// the top flag bit set look like an error to glibc on both arches.
///
/// The one error Linux has is arm64's: a request whose domain byte is
/// `PER_LINUX32` on a kernel without 32-bit EL0 is `-EINVAL`, and stores
/// nothing — so the caller's persona is unchanged and no previous value is
/// returned. x86_64 accepts the same call.
/// # C: O(1)
pub fn sys_personality(args: &SyscallArgs) -> i64 {
    let persona = args.a0 as u32;
    if sched::personality::domains::rejects_domain(
        persona, ARCH_GATES_DOMAIN, sched::personality::domains::SUPPORTS_32BIT_COMPAT) {
        return -(Errno::Einval.as_i32() as i64);
    }
    let cur = match sched::live::current() { Some(cur) => cur, None => return 0 };
    sched::personality::get_set(cur, persona) as i64
}
