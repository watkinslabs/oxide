// LSM self-attribute UAPI constants and admission logic (the LSM UAPI
// numbers and Linux's security-core dispatch). Shared by slots 459/460.
//
// Decision logic lives here, NOT kernel-cfg'd, so the errno ORDERING is
// reachable from the hosted suite; the slot files are
// `#![cfg(target_os = "oxide-kernel")]` and would otherwise be untestable.

use syscall::errno::Errno;

/// `LSM_ID_UNDEF`.
pub const LSM_ID_UNDEF: u64 = 0;
/// `LSM_ID_CAPABILITY`.
pub const LSM_ID_CAPABILITY: u64 = 100;
/// `LSM_ID_LANDLOCK`.
pub const LSM_ID_LANDLOCK: u64 = 110;
/// `LSM_ATTR_UNDEF`.
pub const LSM_ATTR_UNDEF: u32 = 0;
/// `LSM_FLAG_SINGLE` — the only flag `lsm_get_self_attr` accepts.
pub const LSM_FLAG_SINGLE: u32 = 0x0001;
/// `sizeof(struct lsm_ctx)` — four `__u64` before the flexible `ctx[]`.
pub const LSM_CTX_SIZE: u32 = 32;
/// Linux caps `lsm_set_self_attr`'s `size` at one page.
pub const LSM_SET_MAX_SIZE: u32 = 4096;

/// What `security_getselfattr` decides before touching user memory.
/// `Err` short-circuits; `Ok` means "keep going and read user memory".
///
/// Linux order: attr==UNDEF -> EINVAL; size==NULL ->
/// EINVAL; then the user reads (EFAULT); then, if flags is set, it must be
/// exactly LSM_FLAG_SINGLE and uctx must be non-NULL -> EINVAL.
/// # C: O(1)
pub fn getselfattr_precheck(attr: u32, uctx: u64, size_ptr: u64, flags: u32) -> Result<(), Errno> {
    if attr == LSM_ATTR_UNDEF { return Err(Errno::Einval); }
    if size_ptr == 0 { return Err(Errno::Einval); }
    if flags != 0 && (flags != LSM_FLAG_SINGLE || uctx == 0) { return Err(Errno::Einval); }
    Ok(())
}

/// What `security_setselfattr` decides before touching user memory.
///
/// Linux order: any flags -> EINVAL; size < sizeof(struct lsm_ctx) -> EINVAL;
/// size > PAGE_SIZE -> E2BIG. Note E2BIG comes AFTER the too-small check, so
/// a zero size is EINVAL rather than E2BIG.
/// # C: O(1)
pub fn setselfattr_precheck(attr: u32, size: u32, flags: u32) -> Result<(), Errno> {
    if flags != 0 { return Err(Errno::Einval); }
    if attr == LSM_ATTR_UNDEF { return Err(Errno::Einval); }
    if size < LSM_CTX_SIZE { return Err(Errno::Einval); }
    if size > LSM_SET_MAX_SIZE { return Err(Errno::E2big); }
    Ok(())
}

/// `sizeof(u64)` — one `lsm_list_modules` id slot.
pub const LSM_ID_BYTES: u32 = 8;

/// Linux `lsm_idlist[0..lsm_active_cnt]` — the ids `lsm_list_modules` reports.
///
/// `capability` is declared `LSM_ORDER_FIRST` with no `enabled` toggle and no
/// `LSM_FLAG_EXCLUSIVE`, so
/// `lsm_order_append` can never skip it: every
/// `CONFIG_SECURITY=y` kernel reports at least this module, and reporting an
/// empty list would be a kernel with the syscall compiled out — which answers
/// ENOSYS, not success. oxide enforces the POSIX capability model
/// (`sched::cap`, `capget`/`capset`, the `cap_effective` ladder every
/// privileged syscall consults), so `capability` is the one active module.
///
/// `capability` supplies no `getselfattr`/`setselfattr` hook (its hook list is
/// `capability_hooks`), so slots 459/460
/// still answer EOPNOTSUPP — the two facts are consistent, not contradictory.
/// Landlock is the second: it is unconditionally registered wherever its
/// syscalls answer, and slots 444/445/446 here do. Both modules supply
/// `getselfattr`/`setselfattr` hooks for no attribute, so 459/460 still answer
/// EOPNOTSUPP — reporting a module and reporting an attribute for it are
/// separate facts, and inventing the second would be worse than an empty set.
pub const ACTIVE_LSM_IDS: &[u64] = &[LSM_ID_CAPABILITY, LSM_ID_LANDLOCK];

/// `lsm_list_modules`' only argument rule: `flags` is reserved and must be 0.
/// # C: O(1)
pub fn list_modules_precheck(flags: u32) -> Result<(), Errno> {
    if flags != 0 { return Err(Errno::Einval); }
    Ok(())
}

/// The active-module count times one id — the
/// byte count written back through `size` on EVERY path, success or E2BIG.
/// # C: O(1)
pub const fn list_modules_total_size() -> u32 {
    ACTIVE_LSM_IDS.len() as u32 * LSM_ID_BYTES
}

/// `if (usize < total_size) return -E2BIG`. E2BIG,
/// not ENOSPC: the caller re-reads `size` for the required byte count and
/// retries. The write-back happens BEFORE this check, so a too-small buffer
/// still learns the size.
/// # C: O(1)
pub fn list_modules_fits(usize_bytes: u32) -> Result<(), Errno> {
    if usize_bytes < list_modules_total_size() { return Err(Errno::E2big); }
    Ok(())
}

/// Result once every argument is valid and no LSM claims the attribute.
///
/// Linux returns `LSM_RET_DEFAULT(getselfattr)` / `(setselfattr)` — both
/// EOPNOTSUPP — when no module supplies the hook. We register no LSMs, so
/// this is the terminal answer for every well-formed call. It is reached only
/// AFTER the validation above: answering EOPNOTSUPP to a malformed call would
/// hide the caller's bug behind a capability report.
/// # C: O(1)
pub const NO_LSM_RESULT: Errno = Errno::Eopnotsupp;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_rejects_undef_attr_first() {
        // Wrong in several ways at once must still report the attr error,
        // because Linux checks attr before size and before flags.
        assert_eq!(getselfattr_precheck(LSM_ATTR_UNDEF, 0, 0, 0xffff), Err(Errno::Einval));
    }

    #[test]
    fn get_requires_size_pointer() {
        assert_eq!(getselfattr_precheck(100, 0x1000, 0, 0), Err(Errno::Einval));
    }

    #[test]
    fn get_accepts_only_single_flag_and_needs_uctx_with_it() {
        assert_eq!(getselfattr_precheck(100, 0x1000, 0x2000, 2), Err(Errno::Einval));
        // LSM_FLAG_SINGLE without a ctx buffer is invalid.
        assert_eq!(getselfattr_precheck(100, 0, 0x2000, LSM_FLAG_SINGLE), Err(Errno::Einval));
        assert_eq!(getselfattr_precheck(100, 0x1000, 0x2000, LSM_FLAG_SINGLE), Ok(()));
        assert_eq!(getselfattr_precheck(100, 0, 0x2000, 0), Ok(()));
    }

    #[test]
    fn set_rejects_any_flag() {
        assert_eq!(setselfattr_precheck(100, LSM_CTX_SIZE, 1), Err(Errno::Einval));
    }

    #[test]
    fn set_size_below_ctx_is_einval_not_e2big() {
        // Ordering matters: the too-small check precedes the too-big one, so
        // size 0 is EINVAL. Getting this backwards would report E2BIG for an
        // empty buffer.
        assert_eq!(setselfattr_precheck(100, 0, 0), Err(Errno::Einval));
        assert_eq!(setselfattr_precheck(100, LSM_CTX_SIZE - 1, 0), Err(Errno::Einval));
        assert_eq!(setselfattr_precheck(100, LSM_CTX_SIZE, 0), Ok(()));
    }

    #[test]
    fn set_size_above_a_page_is_e2big() {
        assert_eq!(setselfattr_precheck(100, LSM_SET_MAX_SIZE, 0), Ok(()));
        assert_eq!(setselfattr_precheck(100, LSM_SET_MAX_SIZE + 1, 0), Err(Errno::E2big));
    }

    #[test]
    fn no_lsm_answer_is_eopnotsupp() {
        assert_eq!(NO_LSM_RESULT, Errno::Eopnotsupp);
    }

    #[test]
    fn landlock_is_reported_because_its_syscalls_answer() {
        // A module list that omits a mechanism the kernel actually enforces
        // makes a caller believe it is unsandboxed.
        assert!(ACTIVE_LSM_IDS.contains(&LSM_ID_LANDLOCK));
        // Reporting the module does not imply it supplies a self-attribute.
        assert_eq!(NO_LSM_RESULT, Errno::Eopnotsupp);
    }

    #[test]
    fn the_capability_module_is_always_reported() {
        // Linux's `DEFINE_LSM(capability)` has no `enabled`
        // toggle and no EXCLUSIVE flag, so `lsm_active_cnt` is never 0 on a
        // CONFIG_SECURITY=y kernel. An empty list would misreport oxide as a
        // kernel with no capability enforcement at all.
        assert!(ACTIVE_LSM_IDS.contains(&LSM_ID_CAPABILITY));
        assert_eq!(list_modules_total_size(), ACTIVE_LSM_IDS.len() as u32 * 8);
        assert!(list_modules_total_size() > 0);
    }

    #[test]
    fn list_rejects_any_flag() {
        assert_eq!(list_modules_precheck(1), Err(Errno::Einval));
        assert_eq!(list_modules_precheck(0), Ok(()));
    }

    #[test]
    fn a_short_buffer_is_e2big_not_enospc() {
        // The sibling `lsm_set_self_attr` uses E2BIG for "too big"; this one
        // uses E2BIG for "too small". Both match Linux's errno choice.
        let total = list_modules_total_size();
        assert_eq!(list_modules_fits(0), Err(Errno::E2big));
        assert_eq!(list_modules_fits(total - 1), Err(Errno::E2big));
        assert_eq!(list_modules_fits(total), Ok(()));
        assert_eq!(list_modules_fits(total + 1), Ok(()));
    }
}
