// LSM self-attribute UAPI constants and admission logic (Linux
// `include/uapi/linux/lsm.h`, `security/security.c`). Shared by slots 459/460.
//
// Decision logic lives here, NOT kernel-cfg'd, so the errno ORDERING is
// reachable from the hosted suite; the slot files are
// `#![cfg(target_os = "oxide-kernel")]` and would otherwise be untestable.

use syscall::errno::Errno;

/// `LSM_ID_UNDEF`.
pub const LSM_ID_UNDEF: u64 = 0;
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
/// Linux order (`security/security.c`): attr==UNDEF -> EINVAL; size==NULL ->
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
}
