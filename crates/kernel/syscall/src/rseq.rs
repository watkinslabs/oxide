// rseq(2) ABI vocabulary + pure decision ladders per Linux `kernel/rseq.c`
// (`sys_rseq`, `rseq_register`, `rseq_unregister`, `rseq_reregister`,
// `rseq_length_valid`) and `include/linux/rseq_entry.h`
// (`rseq_update_user_cs` — the critical-section abort/fixup).
//
// Pure ABI + arithmetic, no kernel state, so it lives in the boundary crate
// (docs/53) and stays hosted-testable: the kernel side
// (`crates/kernel/sched/src/rseq.rs`) is `#[cfg(target_os = "oxide-kernel")]`
// and its `#[cfg(test)]` blocks never compile under a hosted `cargo test`.
// Single source of truth: the kernel side calls these, never reimplements.

use crate::errno::Errno;

/// `RSEQ_FLAG_UNREGISTER` — tear down this thread's registration.
pub const RSEQ_FLAG_UNREGISTER: u32 = 1 << 0;
/// `RSEQ_FLAG_SLICE_EXT_DEFAULT_ON` — request slice extension on by default.
/// Accepted at registration (Linux `RSEQ_FLAGS_SUPPORTED` names it
/// unconditionally); the kernel only turns the feature on when it advertises
/// `RSEQ_CS_FLAG_SLICE_EXT_AVAILABLE`, which oxide does not.
pub const RSEQ_FLAG_SLICE_EXT_DEFAULT_ON: u32 = 1 << 1;
/// Linux `RSEQ_FLAGS_SUPPORTED` — flag bits legal on a REGISTER call.
pub const RSEQ_FLAGS_SUPPORTED: u32 = RSEQ_FLAG_SLICE_EXT_DEFAULT_ON;

/// Linux `ORIG_RSEQ_SIZE` (`kernel/rseq.c:413`): the pre-extensible
/// `struct rseq` size, and the required alignment for a legacy registration.
pub const ORIG_RSEQ_SIZE: u32 = 32;
/// `offsetof(struct rseq, end)` for the current UAPI layout: `__reserved`
/// sits at byte 32, so the flexible array starts at 33.
pub const RSEQ_END_OFFSET: u32 = 33;
/// Linux `rseq_alloc_align()` = `1 << get_count_order(offsetof(struct rseq, end))`
/// = `1 << 6` for `RSEQ_END_OFFSET == 33`.
pub const RSEQ_ALLOC_ALIGN: u64 = 64;

/// `enum rseq_cpu_id_state::RSEQ_CPU_ID_UNINITIALIZED` ((__u32)-1).
pub const RSEQ_CPU_ID_UNINITIALIZED: u32 = u32::MAX;
/// `enum rseq_cpu_id_state::RSEQ_CPU_ID_REGISTRATION_FAILED` ((__u32)-2).
pub const RSEQ_CPU_ID_REGISTRATION_FAILED: u32 = u32::MAX - 1;

/// `struct rseq` field offsets (`include/uapi/linux/rseq.h`).
pub const RSEQ_OFF_CPU_ID_START: u64 = 0;
pub const RSEQ_OFF_CPU_ID:       u64 = 4;
pub const RSEQ_OFF_RSEQ_CS:      u64 = 8;
pub const RSEQ_OFF_FLAGS:        u64 = 16;
pub const RSEQ_OFF_NODE_ID:      u64 = 20;
pub const RSEQ_OFF_MM_CID:       u64 = 24;
/// `struct rseq::slice_ctrl`, valid only for a v2 registration.
pub const RSEQ_OFF_SLICE_CTRL:   u64 = 28;

/// `RSEQ_CS_FLAG_SLICE_EXT_AVAILABLE`: the kernel supports the v2
/// time-slice extension and owns this read-only advertisement bit.
pub const RSEQ_CS_FLAG_SLICE_EXT_AVAILABLE: u32 = 1 << 4;
/// `RSEQ_CS_FLAG_SLICE_EXT_ENABLED`: the task has enabled the extension
/// through `PR_RSEQ_SLICE_EXTENSION`.
pub const RSEQ_CS_FLAG_SLICE_EXT_ENABLED: u32 = 1 << 5;

/// `rseq_slice_ctrl` request byte. The kernel clears it when it grants or
/// rejects a request; userspace may clear it before that point.
pub const RSEQ_SLICE_REQUEST: u32 = 1 << 0;
/// `rseq_slice_ctrl` grant byte. Only the kernel writes this bit.
pub const RSEQ_SLICE_GRANTED: u32 = 1 << 8;

/// Linux `rseq_slice_ext_get_next`: consume a userspace extension request and
/// publish the kernel grant while preserving future-compatible control bits.
/// `None` means userspace did not request an extension. # C: O(1)
pub const fn take_slice_request(ctrl: u32) -> Option<u32> {
    if ctrl & RSEQ_SLICE_REQUEST == 0 { return None; }
    Some((ctrl & !RSEQ_SLICE_REQUEST) | RSEQ_SLICE_GRANTED)
}

/// A registration longer than the original 32-byte ABI is the extensible v2
/// form. It is the only form whose tail contains `slice_ctrl`.
/// # C: O(1)
pub const fn is_v2(len: u32) -> bool { len > ORIG_RSEQ_SIZE }

/// `struct rseq_cs` field offsets + size (`include/uapi/linux/rseq.h`).
pub const RSEQ_CS_OFF_VERSION:            u64 = 0;
pub const RSEQ_CS_OFF_FLAGS:              u64 = 4;
pub const RSEQ_CS_OFF_START_IP:           u64 = 8;
pub const RSEQ_CS_OFF_POST_COMMIT_OFFSET: u64 = 16;
pub const RSEQ_CS_OFF_ABORT_IP:           u64 = 24;
pub const RSEQ_CS_SIZE:                   u64 = 32;

/// Width of the abort signature word stored immediately below `abort_ip`.
pub const RSEQ_SIG_BYTES: u64 = 4;

/// What `sys_rseq` must do once the argument ladder passes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RseqAction {
    /// Install `(ptr, len, sig)` on the calling thread.
    Register,
    /// Clear the calling thread's registration.
    Unregister,
}

/// One thread's active registration, as the decision ladder sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Registration { pub ptr: u64, pub len: u32, pub sig: u32 }

/// Linux `rseq_length_valid`: a legacy `ORIG_RSEQ_SIZE` registration must be
/// 32-byte aligned; anything larger must be `rseq_alloc_align()`-aligned and
/// cover every kernel-written field. `ptr == 0` can never be aligned-and-valid
/// here because `sys_rseq`'s caller rejects it first (Linux `access_ok` +
/// `IS_ALIGNED(0)` would pass, but a NULL area is rejected by the register
/// ladder below). # C: O(1)
pub fn length_valid(ptr: u64, len: u32) -> bool {
    if len < ORIG_RSEQ_SIZE { return false; }
    if len == ORIG_RSEQ_SIZE { return ptr % ORIG_RSEQ_SIZE as u64 == 0; }
    ptr % RSEQ_ALLOC_ALIGN == 0 && len >= RSEQ_END_OFFSET
}

/// Linux `sys_rseq`'s argument ladder, minus the two uaccess steps
/// (`access_ok` → `EFAULT`, and the unregister id-reset → `EFAULT`) which
/// the kernel side owns because they touch user memory.
///
/// Order is load-bearing and matches `kernel/rseq.c:547`:
/// UNREGISTER first (its own flag mask, then ptr/len match `EINVAL`, then sig
/// mismatch `EPERM`); otherwise unknown flags `EINVAL`; then an already-live
/// registration re-registers (`EINVAL` on ptr/len mismatch, `EPERM` on sig
/// mismatch, `EBUSY` when identical); then length/alignment `EINVAL`.
/// # C: O(1)
pub fn decide(cur: Option<Registration>, ptr: u64, len: u32, flags: u32, sig: u32)
    -> Result<RseqAction, Errno>
{
    if flags & RSEQ_FLAG_UNREGISTER != 0 {
        if flags & !RSEQ_FLAG_UNREGISTER != 0 { return Err(Errno::Einval); }
        let live = match cur { Some(r) if r.ptr != 0 => r, _ => return Err(Errno::Einval) };
        if live.ptr != ptr || live.len != len { return Err(Errno::Einval); }
        if live.sig != sig { return Err(Errno::Eperm); }
        return Ok(RseqAction::Unregister);
    }
    if flags & !RSEQ_FLAGS_SUPPORTED != 0 { return Err(Errno::Einval); }
    if let Some(live) = cur {
        if live.ptr != 0 {
            // Linux `rseq_reregister`.
            if live.ptr != ptr || live.len != len { return Err(Errno::Einval); }
            if live.sig != sig { return Err(Errno::Eperm); }
            return Err(Errno::Ebusy);
        }
    }
    if ptr == 0 { return Err(Errno::Einval); }
    if !length_valid(ptr, len) { return Err(Errno::Einval); }
    Ok(RseqAction::Register)
}

/// What the exit-to-user path must do with a non-NULL `rseq_cs` descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsOutcome {
    /// Interrupted inside the critical section: clear `rseq_cs` and restart
    /// user execution at this address.
    Fixup(u64),
    /// Outside the critical section: clear `rseq_cs`, leave the IP alone.
    Clear,
    /// User space handed the kernel an unusable descriptor. Linux marks the
    /// registration fatal and force-delivers `SIGSEGV`.
    Fatal,
}

/// Linux `rseq_update_user_cs` (`include/linux/rseq_entry.h:380`), split from
/// its uaccess so the arithmetic is testable.
///
/// `ip` is the interrupted user PC, `sig` the registered signature and `usig`
/// the word read from `abort_ip - 4`. `task_size` is the first address above
/// the user half (`hal::USER_VA_END`).
///
/// The `ip - start_ip >= offset` test is Linux's deliberate unsigned wrap: an
/// `ip` below `start_ip` underflows to a huge value and lands outside. The
/// signature check is what stops an attacker who can write `rseq_cs` from
/// redirecting the abort at an arbitrary ROP gadget. # C: O(1)
pub fn cs_outcome(ip: u64, start_ip: u64, post_commit_offset: u64, abort_ip: u64,
                  task_size: u64, sig: u32, usig: u32) -> CsOutcome
{
    if ip.wrapping_sub(start_ip) >= post_commit_offset { return CsOutcome::Clear; }
    if abort_ip >= task_size || abort_ip < RSEQ_SIG_BYTES { return CsOutcome::Fatal; }
    if usig != sig { return CsOutcome::Fatal; }
    CsOutcome::Fixup(abort_ip)
}

/// Linux `rseq_update_user_cs`'s first gate: a `rseq_cs` pointer at or above
/// the user half is fatal, and the whole 32-byte descriptor must fit below it.
/// # C: O(1)
pub fn cs_addr_usable(csaddr: u64, task_size: u64) -> bool {
    csaddr != 0 && csaddr < task_size
        && csaddr.checked_add(RSEQ_CS_SIZE).map(|e| e <= task_size).unwrap_or(false)
}

#[cfg(test)]
#[path = "rseq/tests.rs"]
mod tests;
