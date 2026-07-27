// Alternate signal stack policy (`sigaltstack(2)`, `27§5`). Pure, no_std,
// hosted-testable: NO `live`/registry access, so the exact Linux decision
// table can be proptested without a runqueue. Owners:
//   `syscalls/131_sigaltstack.rs` — the ABI shim, calls `apply`/`report`.
//   `fs::sig_dispatch`            — calls `sigsp`/`report` per delivery.
// Linux references: `kernel/signal.c do_sigaltstack`,
// `include/linux/sched/signal.h {on_sig_stack,sas_ss_flags,sigsp}`.

/// `SS_ONSTACK` (`uapi/linux/signal.h`).
pub const SS_ONSTACK: i32 = 1;
/// `SS_DISABLE`.
pub const SS_DISABLE: i32 = 2;
/// `SS_AUTODISARM` — disarm the alt stack for the duration of a handler
/// that runs on it; `sigreturn` re-arms it from `uc_stack`.
pub const SS_AUTODISARM: i32 = 1 << 31;
/// `SS_FLAG_BITS` — the bits that are flags rather than a mode.
pub const SS_FLAG_BITS: i32 = SS_AUTODISARM;

/// `MINSIGSTKSZ` — the arch's smallest signal-frame-plus-slack budget an
/// alternate stack must be able to hold (`asm/signal.h`). x86_64 keeps the
/// asm-generic 2048; arm64 needs 5120 because its `sigcontext.__reserved`
/// alone is 4096.
#[cfg(target_arch = "aarch64")]
pub const MINSIGSTKSZ: u64 = 5120;
/// See the aarch64 arm above; every other target uses the asm-generic value.
#[cfg(not(target_arch = "aarch64"))]
pub const MINSIGSTKSZ: u64 = 2048;

/// Recorded alternate-stack state (Linux `task_struct::sas_ss_{sp,size,flags}`).
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct AltStack {
    pub sp:    u64,
    pub size:  u64,
    pub flags: i32,
}

/// `do_sigaltstack` rejection reasons, in Linux's own check order.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AltStackError {
    /// Attempt to change the alt stack while executing on it.
    Eperm,
    /// `ss_flags` mode is none of `0` / `SS_ONSTACK` / `SS_DISABLE`.
    Einval,
    /// `ss_size < MINSIGSTKSZ`.
    Enomem,
}

/// Linux `__on_sig_stack` for a downward-growing stack, plus the
/// `SS_AUTODISARM` early-out from `on_sig_stack`: an auto-disarmed stack is
/// by construction never "current", so a corrupted `sp` that happens to land
/// inside it still gets its signal handled.
/// # C: O(1)
pub fn on_sig_stack(sp: u64, alt: AltStack) -> bool {
    if alt.flags & SS_AUTODISARM != 0 { return false; }
    sp > alt.sp && sp - alt.sp <= alt.size
}

/// Linux `sas_ss_flags`: the `ss_flags` value `sigaltstack(2)`'s `oss` and a
/// signal frame's `uc_stack` report — the live mode, not the stored flags,
/// OR'd with the stored `SS_FLAG_BITS`.
/// # C: O(1)
pub fn sas_ss_flags(sp: u64, alt: AltStack) -> i32 {
    let mode = if alt.size == 0 { SS_DISABLE }
               else if on_sig_stack(sp, alt) { SS_ONSTACK }
               else { 0 };
    mode | (alt.flags & SS_FLAG_BITS)
}

/// Linux `sigsp`: the stack base a handler entry SP is carved from. Returns
/// the alt stack top when the action carries `SA_ONSTACK` and the alt stack
/// is armed and not already in use; otherwise the interrupted `sp`.
/// # C: O(1)
pub fn sigsp(sp: u64, alt: AltStack, sa_onstack: bool) -> u64 {
    if use_alt_stack(sp, alt, sa_onstack) { alt.sp.saturating_add(alt.size) } else { sp }
}

/// Whether this delivery switches to the alternate stack — the `sigsp`
/// predicate on its own, so the caller can also drive `SS_AUTODISARM`.
/// # C: O(1)
pub fn use_alt_stack(sp: u64, alt: AltStack, sa_onstack: bool) -> bool {
    sa_onstack && sas_ss_flags(sp, alt) & !SS_FLAG_BITS == 0
}

/// Linux `sas_ss_reset` — what `SS_AUTODISARM` does to the recorded stack
/// once a handler starts running on it.
/// # C: O(1)
pub fn reset() -> AltStack { AltStack { sp: 0, size: 0, flags: SS_DISABLE } }

/// Linux `do_sigaltstack`'s `ss` half. `Ok(None)` = accepted with nothing to
/// store (Linux's "no actual change requested" early return); `Ok(Some(a))` =
/// store `a`. Error order is Linux's: EPERM (on the stack) before EINVAL (bad
/// mode) before ENOMEM (too small).
/// # C: O(1)
pub fn apply(sp: u64, cur: AltStack, new: AltStack) -> Result<Option<AltStack>, AltStackError> {
    if on_sig_stack(sp, cur) { return Err(AltStackError::Eperm); }
    let mode = new.flags & !SS_FLAG_BITS;
    if mode != SS_DISABLE && mode != SS_ONSTACK && mode != 0 {
        return Err(AltStackError::Einval);
    }
    if cur == new { return Ok(None); }
    if mode == SS_DISABLE {
        return Ok(Some(AltStack { sp: 0, size: 0, flags: new.flags }));
    }
    if new.size < MINSIGSTKSZ { return Err(AltStackError::Enomem); }
    Ok(Some(new))
}

#[cfg(test)]
mod tests;
