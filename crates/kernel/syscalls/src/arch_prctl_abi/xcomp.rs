// `ARCH_{GET,REQ}_XCOMP_*` rules — Linux `fpu_xstate_prctl` and
// `xstate_request_perm`.

use syscall::errno::Errno;

/// `XFEATURE_MAX` — one past `XFEATURE_APX`, the highest xstate component
/// number the kernel names. `xstate_request_perm` rejects `idx >= this` with
/// EINVAL, so the exact value is the boundary between EINVAL and EOPNOTSUPP
/// and an off-by-one silently reclassifies one real feature number.
pub const XFEATURE_MAX: u64 = 20;

/// `XFEATURE_XTILE_CFG` / `XFEATURE_XTILE_DATA` — the AMX pair, and the only
/// entries `xstate_prctl_req[]` populates.
pub const XFEATURE_XTILE_CFG: u64 = 17;
pub const XFEATURE_XTILE_DATA: u64 = 18;
/// `XFEATURE_MASK_XTILE_DATA` — the mask `xstate_prctl_req[XTILE_DATA]`
/// holds. It is the DATA bit alone, not the tile pair: the request grants the
/// dynamically-enabled component, and `XTILE_CFG` is already in the default
/// set on a CPU that has AMX.
pub const XFEATURE_MASK_XTILE_DATA: u64 = 1 << XFEATURE_XTILE_DATA;

/// `XFEATURE_MASK_FPSSE` — x87 + SSE, the two components every XSAVE-capable
/// CPU has and the whole user mask on a kernel that fell back to FXSAVE.
pub const XFEATURE_MASK_FPSSE: u64 = 0b11;

/// `XFEATURE_MASK_USER_SUPPORTED` — every user xstate component the kernel
/// knows how to save, restore and lay out in a signal frame. Components
/// outside it (PT, PASID, CET, LBR and the reserved slots) are supervisor or
/// unimplemented, and reporting one to userspace would advertise state that
/// never survives a context switch.
pub const XFEATURE_MASK_USER_SUPPORTED: u64 =
    (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7)
    | (1 << 9)                                   // PKRU
    | (1 << XFEATURE_XTILE_CFG) | (1 << XFEATURE_XTILE_DATA)
    | (1 << 19);                                 // APX

/// `XFEATURE_MASK_USER_DYNAMIC` — the components a thread group must ASK for
/// before it may use them. Exactly `XTILE_DATA`, because it is the only state
/// large enough that Linux keeps it behind XFD rather than in every task's
/// default buffer.
pub const XFEATURE_MASK_USER_DYNAMIC: u64 = XFEATURE_MASK_XTILE_DATA;

/// `ARCH_GET_XCOMP_SUPP` — `fpu_user_cfg.max_features |
/// fpu_user_cfg.legacy_features`, derived here from the live XCR0 the FPU
/// owner programmed.
///
/// XCR0 is the right source: it is by definition the USER xstate enable mask
/// (supervisor components live in `IA32_XSS`), and it holds exactly the
/// components this kernel's `xsave`/`xrstor` actually move. On a kernel that
/// fell back to FXSAVE there is no XCR0 and the answer is the legacy x87+SSE
/// pair, which is precisely the state such a kernel saves.
/// # C: O(1)
pub fn xcomp_supported(xsave_active: bool, xcr0: u64) -> u64 {
    if !xsave_active { return XFEATURE_MASK_FPSSE; }
    (xcr0 & XFEATURE_MASK_USER_SUPPORTED) | XFEATURE_MASK_FPSSE
}

/// `ARCH_GET_XCOMP_PERM` / `ARCH_GET_XCOMP_GUEST_PERM` —
/// `xstate_get_{host,guest}_group_perm() & XFEATURE_MASK_USER_SUPPORTED`.
///
/// Permission is NOT support: a thread group starts with
/// `fpu_kernel_cfg.default_features`, which is the supported set MINUS the
/// dynamically-enabled components. So a CPU with AMX reports XTILE_DATA in
/// SUPP but not in PERM until `ARCH_REQ_XCOMP_PERM` grants it, and a runtime
/// that read PERM as SUPP would execute AMX instructions that `#UD`.
///
/// Host and guest groups start from the same default, so `guest` does not
/// change the answer until a request has moved one of them.
/// # C: O(1)
pub fn xcomp_permitted(supported: u64, granted: u64) -> u64 {
    ((supported & !XFEATURE_MASK_USER_DYNAMIC) | granted) & XFEATURE_MASK_USER_SUPPORTED
}

/// `xstate_request_perm(idx, guest)`.
///
/// The index is the HIGHEST feature number of the facility being asked for,
/// and the permission table has exactly one non-zero entry (`XTILE_DATA`).
/// So an index at or above `XFEATURE_MAX` is EINVAL, and every valid index
/// that names no dynamically-enabled facility — or one the CPU/kernel does
/// not offer — is **EOPNOTSUPP**, not EINVAL.
///
/// Returns `Ok(mask)` with the components to add to the group's permission
/// set. `Ok(0)` means the permission already held (Linux's lockless quick
/// check returning 0 without touching the group).
/// # C: O(1)
pub fn xcomp_request(idx: u64, supported: u64, permitted: u64) -> Result<u64, i64> {
    if idx >= XFEATURE_MAX { return Err(-(Errno::Einval.as_i32() as i64)); }
    let requested = if idx == XFEATURE_XTILE_DATA { XFEATURE_MASK_XTILE_DATA } else { 0 };
    if requested == 0 { return Err(-(Errno::Eopnotsupp.as_i32() as i64)); }
    if supported & requested != requested { return Err(-(Errno::Eopnotsupp.as_i32() as i64)); }
    if permitted & requested == requested { return Ok(0); }
    Ok(requested)
}
