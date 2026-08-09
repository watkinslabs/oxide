// `ioperm(2)` / `iopl(2)` admission ladders, in the reference's order.
//
// Ordering is the contract, not an implementation detail: a caller that gets
// EPERM where the reference returns EINVAL learns it lacks privilege for a
// request that was malformed regardless of privilege, and probes that use the
// distinction to feature-detect draw the wrong conclusion.

use syscall::errno::Errno;

use super::bitmap::IO_BITMAP_BITS;

/// Highest `iopl` level. 3 is the only value that grants anything; 0-2 all
/// mean "no port access", and the reference still validates them.
pub const IOPL_MAX: u32 = 3;

/// What `iopl` should do once the ladder passes.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum IoplAction {
    /// Level already equals the current one — return 0 touching nothing.
    Unchanged,
    /// Adopt `level` and reprogram the TSS window.
    Set(u8),
}

/// `ksys_ioperm`'s validation, before any allocation:
///
/// 1. `from + num <= from` OR `from + num > IO_BITMAP_BITS` → EINVAL. The
///    first arm also rejects `num == 0` (the sum equals `from`) and any
///    wrapping sum, which is why it is a wrapping add and not a checked one.
/// 2. Only a `turn_on` request needs `CAP_SYS_RAWIO` → EPERM. Dropping
///    permissions is unprivileged, so a task that gained ports and then
///    dropped privilege can still give them back.
/// # C: O(1)
pub fn ioperm_check(from: u64, num: u64, turn_on: bool, capable: bool) -> Result<(), Errno> {
    let end = from.wrapping_add(num);
    if end <= from || end > IO_BITMAP_BITS { return Err(Errno::Einval); }
    if turn_on && !capable { return Err(Errno::Eperm); }
    Ok(())
}

/// `SYSCALL_DEFINE1(iopl)`'s ladder:
///
/// 1. `level > 3` → EINVAL, before any privilege test.
/// 2. `level == old` → success, changing nothing. This runs BEFORE the
///    capability test, so an unprivileged task re-asserting the level it
///    already holds succeeds rather than getting EPERM.
/// 3. Raising the level (`level > old`) needs `CAP_SYS_RAWIO` → EPERM.
///    LOWERING it never does.
/// # C: O(1)
pub fn iopl_check(level: u32, old: u8, capable: bool) -> Result<IoplAction, Errno> {
    if level > IOPL_MAX { return Err(Errno::Einval); }
    if level == old as u32 { return Ok(IoplAction::Unchanged); }
    if level > old as u32 && !capable { return Err(Errno::Eperm); }
    Ok(IoplAction::Set(level as u8))
}
