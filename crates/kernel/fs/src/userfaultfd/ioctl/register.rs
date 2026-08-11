// UFFDIO_REGISTER / UFFDIO_UNREGISTER / UFFDIO_WAKE.

use alloc::sync::Arc;
use syscall::errno::Errno;

use crate::userbuf::{validate_user_buf, validate_user_buf_writable};
use crate::userfaultfd::{policy, uapi::*, RegisteredRange, UfData};
use crate::userfaultfd::policy::RegVma;

use super::structs::{ctx_is, err, read_req, UffdioRange, UffdioRegister};

/// Bind this context to every VMA overlapping the range, arm the requested
/// modes there, and report the ops guaranteed to work on it.
/// # C: O(N_vmas)
pub fn ioc_register(ufd: &Arc<UfData>, arg: u64) -> i64 {
    if let Err(rv) = validate_user_buf_writable(arg, UFFDIO_REGISTER_SIZE, 1) { return rv; }
    let Ok(reg) = read_req::<UffdioRegister>(arg) else { return err(Errno::Efault) };
    // The mode ladder runs BEFORE range validation: a garbage mode word is
    // EINVAL whatever the range says.
    let modes = match policy::check_register_mode(reg.mode) { Ok(m) => m, Err(e) => return err(e) };
    if let Err(e) = policy::validate_range(reg.range.start, reg.range.len) { return err(e); }
    let start = reg.range.start;
    let end   = start + reg.range.len;
    let Some(mm) = ufd.mm() else { return err(Errno::Enomem) };
    let wp_async = policy::wp_async(ufd.features.load(core::sync::atomic::Ordering::Acquire));
    if let Err(e) = scan_registerable(&mm, start, end, ufd, modes, wp_async) { return err(e); }
    ufd.state.lock().ranges.push(RegisteredRange { start, end, mode: reg.mode });
    let ctx: Arc<dyn vmm::UffdContext> = ufd.clone();
    mm.set_uffd(start, end, ctx, modes);
    let ioctls = policy::register_ioctls(reg.mode);
    // `put_user(ioctls, &user_uffdio_register->ioctls)`: the registration is
    // done, but a monitor that never learns which ops are legal on the range
    // cannot use it, so the failed write-back is EFAULT.
    if uaccess::copy_to_user(arg + UFFDIO_REGISTER_IOCTLS_OFF, &ioctls.to_ne_bytes()).is_err() {
        return err(Errno::Efault);
    }
    0
}

/// The per-VMA registration scan over `[start, end)`: at least one VMA must
/// overlap (else EINVAL), and each must pass the ladder. Holes inside the
/// range are not an error — the scan simply skips them.
/// # C: O(N_vmas)
fn scan_registerable(mm: &vmm::AddressSpace, start: u64, end: u64, ufd: &Arc<UfData>,
                     modes: vmm::VmaFlags, wp_async: bool) -> Result<(), Errno> {
    let vmas = mm.uffd_vmas_in(start, end);
    if vmas.is_empty() { return Err(Errno::Einval); }
    for v in &vmas {
        policy::check_register_vma(&RegVma {
            anonymous: v.anonymous,
            shmem: v.shmem,
            file_backed: v.file.is_some(),
            may_write: v.may_write,
            owned_by_other_uffd: v.ctx.as_ref().is_some_and(|c| !ctx_is(c, ufd)),
        }, modes, wp_async)?;
    }
    Ok(())
}

/// Drop the range record and clear the per-VMA registration, modes included.
/// # C: O(N_vmas)
pub fn ioc_unregister(ufd: &UfData, arg: u64) -> i64 {
    if let Err(rv) = validate_user_buf(arg, UFFDIO_RANGE_SIZE, 1) { return rv; }
    let Ok(r) = read_req::<UffdioRange>(arg) else { return err(Errno::Efault) };
    if let Err(e) = policy::validate_range(r.start, r.len) { return err(e); }
    let end = r.start + r.len;
    let Some(mm) = ufd.mm() else { return err(Errno::Enomem) };
    ufd.state.lock().ranges.retain(|reg| !(reg.start == r.start && reg.end == end));
    mm.clear_uffd(r.start, end);
    0
}

/// Wake blocked faulters without supplying a page — they re-fault.
/// # C: O(N_faulters)
pub fn ioc_wake(ufd: &UfData, arg: u64) -> i64 {
    if let Err(rv) = validate_user_buf(arg, UFFDIO_RANGE_SIZE, 1) { return rv; }
    let Ok(r) = read_req::<UffdioRange>(arg) else { return err(Errno::Efault) };
    if let Err(e) = policy::validate_range(r.start, r.len) { return err(e); }
    ufd.wake_faulters();
    0
}
