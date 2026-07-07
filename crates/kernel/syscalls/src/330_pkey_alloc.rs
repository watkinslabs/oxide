// 330 pkey_alloc — one syscall, one file (docs/53 §0). Moved verbatim from misc.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::misc::misc_common::errno;

/// `pkey_alloc(flags, access_rights)` — slot 330. No PKU/PKRU enforcement
/// (no CR4.PKE, no per-PTE protection-key bits), so a protection key cannot
/// protect anything. Linux returns ENOSYS when X86_FEATURE_OSPKE is absent —
/// do the same instead of handing back a valid key that silently isn't
/// enforced (an in-process isolation lie).
/// # C: O(1)
pub fn sys_pkey_alloc(_args: &SyscallArgs) -> i64 { errno(Errno::Enosys) }
