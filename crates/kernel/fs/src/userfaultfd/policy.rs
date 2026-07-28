// userfaultfd(2) decision logic — every validation ladder, errno choice and
// reply bitmap, as pure functions over plain scalars.
//
// UNGATED on purpose (`docs/53` + the phantom-test rule in CLAUDE.md): the
// ioctl slot bodies and the fault path are `target_os = "oxide-kernel"`, so a
// `#[cfg(test)]` block inside them never compiles. Keeping the decisions here
// is what makes `tests/policy.rs` a real gate.
//
// Linux source of truth: `/home/nd/oxide/linux-master` v7.2.0-rc4,
// `mm/userfaultfd.c` (userfaultfd moved out of `fs/userfaultfd.c` in this
// tree) and `include/uapi/linux/userfaultfd.h`.

use syscall::errno::Errno;

use super::uapi::*;

/// Page mask used by `validate_range` (Linux `PAGE_MASK`).
const PAGE_MASK: u64 = !(hal::PAGE_SIZE_BYTES - 1);

/// Linux `mm->task_size` for a native 64-bit task: the first VA above the
/// user half.
#[inline]
fn task_size() -> u64 { hal::USER_VA_END }

/// Linux `validate_unaligned_range` (`mm/userfaultfd.c`): `len` must be a
/// non-zero page multiple and `[start, start+len)` must fit below
/// `mm->task_size`; `start` itself may be unaligned (only `uffdio_copy.src`
/// uses this variant). Every failure is EINVAL.
/// # C: O(1)
pub fn validate_unaligned_range(start: u64, len: u64) -> Result<(), Errno> {
    if len & !PAGE_MASK != 0 { return Err(Errno::Einval); }
    if len == 0 { return Err(Errno::Einval); }
    if start >= task_size() { return Err(Errno::Einval); }
    if len > task_size() - start { return Err(Errno::Einval); }
    if start.checked_add(len).is_none_or(|end| end <= start) { return Err(Errno::Einval); }
    Ok(())
}

/// Linux `validate_range` — `validate_unaligned_range` plus a page-aligned
/// `start`. Used for every range a uffd op INSTALLS into or REGISTERS.
/// # C: O(1)
pub fn validate_range(start: u64, len: u64) -> Result<(), Errno> {
    if start & !PAGE_MASK != 0 { return Err(Errno::Einval); }
    validate_unaligned_range(start, len)
}

/// Linux `userfaultfd_syscall_allowed(flags)` (`mm/userfaultfd.c`), verbatim:
///
/// ```text
/// if (flags & UFFD_USER_MODE_ONLY) return true;   /* user-only always OK */
/// if (capable(CAP_SYS_PTRACE))     return true;   /* privileged always OK */
/// return sysctl_unprivileged_userfaultfd;         /* else sysctl-gated    */
/// ```
///
/// `capable()` is `ns_capable(&init_user_ns, …)`, so the caller must resolve
/// CAP_SYS_PTRACE in the INITIAL user namespace — root inside an unprivileged
/// userns must not qualify.
/// # C: O(1)
pub fn syscall_allowed(flags: u32, cap_sys_ptrace: bool, sysctl_unprivileged: bool) -> bool {
    if flags & UFFD_USER_MODE_ONLY != 0 { return true; }
    if cap_sys_ptrace { return true; }
    sysctl_unprivileged
}

/// `userfaultfd(2)` entry ladder. Linux runs the EPERM gate in
/// `SYSCALL_DEFINE1(userfaultfd)` BEFORE `new_userfaultfd` rejects unknown
/// flag bits, so an unprivileged caller passing garbage flags sees EPERM, not
/// EINVAL — an observable ordering, not a detail.
/// # C: O(1)
pub fn check_create(flags: u32, cap_sys_ptrace: bool, sysctl_unprivileged: bool)
    -> Result<(), Errno> {
    if !syscall_allowed(flags, cap_sys_ptrace, sysctl_unprivileged) { return Err(Errno::Eperm); }
    if flags & !UFFD_ALL_FLAGS != 0 { return Err(Errno::Einval); }
    Ok(())
}

/// Linux `userfaultfd_is_initialized(ctx)` — `ctx->features` carries the
/// kernel-private `UFFD_FEATURE_INITIALIZED` bit once `UFFDIO_API` has run.
/// # C: O(1)
pub fn is_initialized(ctx_features: u64) -> bool {
    ctx_features & feature::INITIALIZED != 0
}

/// Linux `userfaultfd_ioctl`: `if (cmd != UFFDIO_API && !userfaultfd_is_
/// initialized(ctx)) return -EINVAL;` — every op except API needs a completed
/// handshake first.
/// # C: O(1)
pub fn check_ioctl_ordering(req: u64, ctx_features: u64) -> Result<(), Errno> {
    if req != UFFDIO_API && !is_initialized(ctx_features) { return Err(Errno::Einval); }
    Ok(())
}

/// What `UFFDIO_API` writes back and installs on success.
pub struct ApiReply {
    /// `uffdio_api.features` — every feature this kernel offers.
    pub features: u64,
    /// `uffdio_api.ioctls` — ops valid on the fd (`UFFD_API_IOCTLS`).
    pub ioctls: u64,
    /// New `ctx->features` (requested set | `UFFD_FEATURE_INITIALIZED`).
    pub ctx_features: u64,
}

/// Linux `userfaultfd_api` (`mm/userfaultfd.c`), in its exact order:
/// wrong API → EINVAL; `EVENT_FORK` without CAP_SYS_PTRACE → EPERM;
/// a request for any feature the kernel does not offer → EINVAL; a second
/// handshake (`cmpxchg(&ctx->features, 0, ctx_features) != 0`) → EINVAL.
///
/// The `cmpxchg` compares against 0, so repeating `UFFDIO_API` with
/// `features == 0` succeeds (`ctx_features` still carries INITIALIZED, so the
/// compare-against-0 fails only once a prior handshake stored it) — reproduce
/// that, do not "improve" it.
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

/// Linux `userfaultfd_register`'s mode ladder, which runs BEFORE
/// `validate_range`:
///
/// ```text
/// if (!uffdio_register.mode) goto out;                        /* EINVAL */
/// if (uffdio_register.mode & ~UFFD_API_REGISTER_MODES) goto out;
/// if (mode & MODE_WP    && !pgtable_supports_uffd_wp()) goto out;
/// if (mode & MODE_MINOR && !CONFIG_HAVE_ARCH_USERFAULTFD_MINOR) goto out;
/// ```
///
/// oxide has neither uffd-wp PTE bits nor MINOR-fault interception, so both
/// take Linux's own unsupported-kernel arm and return EINVAL. That is the
/// point: the previous code ACCEPTED `MODE_WP`, recorded the range and then
/// never delivered a WP fault, so a monitor relying on write-protection for a
/// security property was silently unprotected.
/// # C: O(1)
pub fn check_register_mode(mode: u64) -> Result<(), Errno> {
    if mode == 0 { return Err(Errno::Einval); }
    if mode & !UFFD_API_REGISTER_MODES != 0 { return Err(Errno::Einval); }
    if mode & UFFDIO_REGISTER_MODE_WP != 0 { return Err(Errno::Einval); }
    if mode & UFFDIO_REGISTER_MODE_MINOR != 0 { return Err(Errno::Einval); }
    Ok(())
}

/// `uffdio_register.ioctls` reply for an accepted `mode`. Linux masks
/// `_UFFDIO_WRITEPROTECT` out unless MODE_WP and `_UFFDIO_CONTINUE` out unless
/// MODE_MINOR; neither can survive [`check_register_mode`], so the reply is
/// the implemented base set.
/// # C: O(1)
pub fn register_ioctls(mode: u64) -> u64 {
    let mut out = UFFD_API_RANGE_IOCTLS;
    if mode & UFFDIO_REGISTER_MODE_WP == 0 { out &= !(1u64 << slot::WRITEPROTECT); }
    if mode & UFFDIO_REGISTER_MODE_MINOR == 0 { out &= !(1u64 << slot::CONTINUE); }
    out
}

/// The facts [`check_register_vma`] needs about one VMA overlapping the
/// range `UFFDIO_REGISTER` was asked to cover.
#[derive(Copy, Clone, Debug)]
pub struct RegVma {
    /// Linux `vma_can_userfault(cur, vm_flags, wp_async)`. Linux accepts
    /// anonymous, shmem and hugetlbfs VMAs (the three with `vm_uffd_ops`) and
    /// rejects everything else, including ordinary file mappings and
    /// `VM_SPECIAL`/`VM_PFNMAP` device ranges. oxide implements the anonymous
    /// `vm_uffd_ops` only, so the caller sets this from `VmaBacking::Anonymous`.
    pub can_userfault: bool,
    /// Linux `cur->vm_flags & VM_MAYWRITE`.
    pub may_write: bool,
    /// Linux `cur->vm_userfaultfd_ctx.ctx && cur->vm_userfaultfd_ctx.ctx != ctx`.
    pub owned_by_other_uffd: bool,
}

/// Linux `userfaultfd_register`'s per-VMA scan, in order:
///
/// ```text
/// ret = -EINVAL; if (!vma_can_userfault(cur, vm_flags, wp_async)) goto out_unlock;
/// ret = -EPERM;  if (unlikely(!(cur->vm_flags & VM_MAYWRITE))) goto out_unlock;
/// ret = -EBUSY;  if (cur->vm_userfaultfd_ctx.ctx &&
///                    cur->vm_userfaultfd_ctx.ctx != ctx) goto out_unlock;
/// ```
///
/// The EPERM arm is a real permission gate, not bookkeeping: its comment says
/// `UFFDIO_COPY` fills holes even without PROT_WRITE, so registration is where
/// write permission on the backing must be proven. The EBUSY arm is what makes
/// "the VMA carries a uffd ctx" a usable authorisation fact for
/// [`check_dst_vma`] — two fds can never own one VMA.
/// # C: O(1)
pub fn check_register_vma(v: &RegVma) -> Result<(), Errno> {
    if !v.can_userfault { return Err(Errno::Einval); }
    if !v.may_write { return Err(Errno::Eperm); }
    if v.owned_by_other_uffd { return Err(Errno::Ebusy); }
    Ok(())
}

/// The destination VMA facts [`check_dst_vma`] needs, lifted out of `vmm::Vma`
/// so the ladder is testable without an `AddressSpace`.
#[derive(Copy, Clone, Debug)]
pub struct DstVma {
    /// `vma->vm_end`.
    pub end: u64,
    /// `vma->vm_userfaultfd_ctx.ctx != NULL`.
    pub uffd_registered: bool,
    /// `vma->vm_flags & VM_UFFD_WP`. Always false while
    /// [`check_register_mode`] refuses `UFFDIO_REGISTER_MODE_WP`.
    pub uffd_wp: bool,
}

/// THE security ladder for `UFFDIO_COPY` / `UFFDIO_ZEROPAGE`: Linux
/// `uffd_mfill_lock` → `find_vma_and_prepare_anon` → `validate_dst_vma`
/// (`mm/userfaultfd.c`).
///
/// ```text
/// vma = vma_lookup(mm, dst_start);
/// if (!vma) return ERR_PTR(-ENOENT);              /* no VMA covers dst   */
/// if (dst_end > vma->vm_end) return -ENOENT;      /* range leaves the VMA */
/// if (!vma->vm_userfaultfd_ctx.ctx) return -ENOENT;  /* not uffd-registered */
/// ```
///
/// Without it, COPY/ZEROPAGE installed a fresh writable frame at ANY
/// page-aligned user VA — an arbitrary-address kernel-assisted memory write
/// reachable from any process holding a uffd fd. Linux checks the ctx pointer
/// for NULL-ness rather than identity (`validate_dst_vma`'s comment: the check
/// exists to "enforce the VM_MAYWRITE check done at uffd registration time"),
/// and registration already refuses a VMA owned by a different uffd with
/// EBUSY, so non-NULL means "some uffd registered this VMA".
///
/// `want_wp` is `MFILL_ATOMIC_WP` (`UFFDIO_COPY_MODE_WP`), whose VMA check
/// Linux runs in `mfill_get_vma` AFTER the lookup — so a MODE_WP copy at an
/// unmapped address reports ENOENT, not EINVAL. That order is observable.
/// # C: O(1)
pub fn check_dst_vma(dst_end: u64, vma: Option<DstVma>, want_wp: bool) -> Result<(), Errno> {
    let Some(v) = vma else { return Err(Errno::Enoent) };
    if dst_end > v.end { return Err(Errno::Enoent); }
    if !v.uffd_registered { return Err(Errno::Enoent); }
    if want_wp && !v.uffd_wp { return Err(Errno::Einval); }
    Ok(())
}

/// Linux `userfaultfd_copy`: `if (uffdio_copy.mode & ~(DONTWAKE|WP)) → EINVAL`.
/// Only the unknown-bit test lives here; `MODE_WP`'s "the VMA must be
/// WP-registered" half is [`check_dst_vma`]'s `want_wp`, because Linux runs it
/// after the destination lookup.
/// # C: O(1)
pub fn check_copy_mode(mode: u64) -> Result<(), Errno> {
    if mode & !(UFFDIO_COPY_MODE_DONTWAKE | UFFDIO_COPY_MODE_WP) != 0 { return Err(Errno::Einval); }
    Ok(())
}

/// Linux `userfaultfd_zeropage`: `if (mode & ~ZEROPAGE_MODE_DONTWAKE)` → EINVAL.
/// # C: O(1)
pub fn check_zeropage_mode(mode: u64) -> Result<(), Errno> {
    if mode & !UFFDIO_ZEROPAGE_MODE_DONTWAKE != 0 { return Err(Errno::Einval); }
    Ok(())
}

/// Linux's fill return protocol (`userfaultfd_copy` / `userfaultfd_zeropage`
/// tails): the `copy`/`zeropage` field carries the byte count (or the negative
/// errno when nothing was installed), and the ioctl itself returns
/// `range.len == requested ? 0 : -EAGAIN`. Note EAGAIN — NOT ENOMEM, which is
/// what the old short-install path returned.
/// # C: O(1)
pub fn fill_retval(installed: u64, requested: u64, err: Option<Errno>) -> (i64, i64) {
    if installed == 0 {
        if let Some(e) = err { let rv = -(e.as_i32() as i64); return (rv, rv); }
    }
    let rv = if installed == requested { 0 } else { -(Errno::Eagain.as_i32() as i64) };
    (rv, installed as i64)
}

/// Whether the fill path should wake blocked faulters (Linux: everything
/// except `MODE_DONTWAKE`, and only when at least one page was installed).
/// # C: O(1)
pub fn should_wake(mode: u64, installed: u64) -> bool {
    installed != 0 && mode & UFFDIO_COPY_MODE_DONTWAKE == 0
}

/// Linux `handle_userfault` (`mm/userfaultfd.c`):
/// `if (!(vmf->flags & FAULT_FLAG_USER) && (ctx->flags & UFFD_USER_MODE_ONLY)) goto out;`
/// where `out` returns `VM_FAULT_SIGBUS`. Returns `true` when the fault may be
/// handed to the monitor. Without this the `UFFD_USER_MODE_ONLY` flag — the
/// escape hatch [`syscall_allowed`] grants every unprivileged caller — is a
/// label with no behaviour: an unprivileged uffd could still park the KERNEL
/// inside a `copy_from_user` on a registered page.
/// # C: O(1)
pub fn may_deliver_fault(ctx_flags: u32, user_mode: bool) -> bool {
    user_mode || ctx_flags & UFFD_USER_MODE_ONLY == 0
}
