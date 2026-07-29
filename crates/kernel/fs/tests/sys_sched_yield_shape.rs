// This integration test compiles production modules directly via `#[path]` to
// assert their ABI shape, and exercises only the part of each module the shape
// under test needs. dead_code here measures the test's reach, not the kernel's
// -- the real signal lives in `xtask kernel`, which is dead_code-clean.
#![allow(dead_code)]
use syscall::SyscallArgs;

#[path = "../../syscalls/src/024_sched_yield.rs"]
mod sched_yield_syscall;

fn args() -> SyscallArgs {
    SyscallArgs { a0: u64::MAX, a1: 0xdead_beef, a2: 1, a3: 2, a4: 3, a5: 4 }
}

#[test]
fn sched_yield_returns_zero_and_ignores_arguments() {
    assert_eq!(sched_yield_syscall::sys_sched_yield(&args()), 0);
}
