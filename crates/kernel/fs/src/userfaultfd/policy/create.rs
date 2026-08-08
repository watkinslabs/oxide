// fd creation, the UFFDIO_API handshake, ioctl ordering, and the one gate that
// decides whether a fault may be handed to a monitor at all.

use syscall::errno::Errno;

use crate::userfaultfd::uapi::*;

/// The creation gate:
///
/// ```text
/// user-mode-only            → allowed
/// privileged (ptrace cap)   → allowed
/// otherwise                 → the vm.unprivileged_userfaultfd sysctl decides
/// ```
///
/// The capability must be held in the INITIAL user namespace, or any user
/// could reach the privileged arm by first unsharing a user namespace where
/// they are root — exactly the bypass the sysctl exists to stop.
/// # C: O(1)
pub fn syscall_allowed(flags: u32, cap_sys_ptrace: bool, sysctl_unprivileged: bool) -> bool {
    if flags & UFFD_USER_MODE_ONLY != 0 { return true; }
    if cap_sys_ptrace { return true; }
    sysctl_unprivileged
}

/// `userfaultfd(2)` entry ladder. The EPERM gate runs BEFORE unknown flag bits
/// are rejected, so an unprivileged caller passing garbage flags sees EPERM,
/// not EINVAL — an observable ordering, not a detail.
/// # C: O(1)
pub fn check_create(flags: u32, cap_sys_ptrace: bool, sysctl_unprivileged: bool)
    -> Result<(), Errno> {
    if !syscall_allowed(flags, cap_sys_ptrace, sysctl_unprivileged) { return Err(Errno::Eperm); }
    if flags & !UFFD_ALL_FLAGS != 0 { return Err(Errno::Einval); }
    Ok(())
}

/// Whether the API handshake has run: the context's feature word carries the
/// kernel-private INITIALIZED bit once it has.
/// # C: O(1)
pub fn is_initialized(ctx_features: u64) -> bool {
    ctx_features & feature::INITIALIZED != 0
}

/// Every op except the handshake itself needs a completed handshake first.
/// # C: O(1)
pub fn check_ioctl_ordering(req: u64, ctx_features: u64) -> Result<(), Errno> {
    if req != UFFDIO_API && !is_initialized(ctx_features) { return Err(Errno::Einval); }
    Ok(())
}

/// What `UFFDIO_API` writes back and installs on success.
pub struct ApiReply {
    /// `uffdio_api.features` — every feature this kernel offers.
    pub features: u64,
    /// `uffdio_api.ioctls` — ops valid on the fd.
    pub ioctls: u64,
    /// New context features (requested set | INITIALIZED).
    pub ctx_features: u64,
}

/// The handshake, in its exact order: wrong API → EINVAL; a fork-event request
/// without the ptrace capability → EPERM; a request for any feature this
/// kernel does not offer → EINVAL; a second handshake → EINVAL.
///
/// The repeat test compares the stored word against 0, so repeating the
/// handshake with `features == 0` succeeds exactly once (the stored word then
/// carries INITIALIZED and is no longer 0) — reproduce that, do not "improve"
/// it: a monitor probing the API twice depends on it.
/// # C: O(1)
pub fn api_negotiate(api: u64, req_features: u64, cap_sys_ptrace: bool, ctx_features: u64)
    -> Result<ApiReply, Errno> {
    if api != UFFD_API { return Err(Errno::Einval); }
    if req_features & feature::EVENT_FORK != 0 && !cap_sys_ptrace { return Err(Errno::Eperm); }
    if req_features & !UFFD_API_FEATURES != 0 { return Err(Errno::Einval); }
    if ctx_features != 0 { return Err(Errno::Einval); }
    Ok(ApiReply {
        features: UFFD_API_FEATURES,
        ioctls: UFFD_API_IOCTLS,
        ctx_features: req_features | feature::INITIALIZED,
    })
}

/// Whether a fault may be handed to the monitor. Returns false for a
/// kernel-mode access against a user-mode-only context. Without this the
/// `UFFD_USER_MODE_ONLY` flag — the escape hatch [`syscall_allowed`] grants
/// every unprivileged caller — is a label with no behaviour: an unprivileged
/// uffd could still park the KERNEL inside a copy-from-user on a registered
/// page.
/// # C: O(1)
pub fn may_deliver_fault(ctx_flags: u32, user_mode: bool) -> bool {
    user_mode || ctx_flags & UFFD_USER_MODE_ONLY == 0
}
