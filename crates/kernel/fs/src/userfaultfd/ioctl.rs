// UFFDIO_* dispatch for userfaultfd(2) — the ABI shim only (`docs/53`):
// validate the user object, hand the decision to `policy.rs`, call one work
// function, encode the reply. Linux `userfaultfd_ioctl` and its per-command
// handlers in `mm/userfaultfd.c`.
//
// Every range op targets `ctx->mm` — the address space captured when the fd
// was created — NOT `current`'s. The fd survives `fork`, `execve` and
// `SCM_RIGHTS`, so resolving the destination against the caller would let a
// process that merely HOLDS the fd install pages into its own address space.

use alloc::sync::Arc;

use hal::UserVirtAddr;
use syscall::errno::Errno;

use crate::userbuf::{validate_user_buf, validate_user_buf_readable, validate_user_buf_writable};
use super::policy::{self, DstVma, RegVma};
use super::uapi::*;
use super::{as_uffd, install_pages, RegisteredRange, UfData};

/// `struct uffdio_api` — `{ api, features, ioctls }`. The 24 (0x18) in the
/// `UFFDIO_API` request encoding is the authority on this size; the previous
/// two-field version left `ioctls` unwritten in every monitor's buffer.
#[repr(C)]
#[derive(Copy, Clone, Default)]
struct UffdioApi { api: u64, features: u64, ioctls: u64 }

#[repr(C)]
#[derive(Copy, Clone)]
struct UffdioRange { start: u64, len: u64 }

/// `struct uffdio_register` — 32 bytes.
#[repr(C)]
#[derive(Copy, Clone)]
struct UffdioRegister { range: UffdioRange, mode: u64, ioctls: u64 }

/// `struct uffdio_copy` — 40 bytes.
#[repr(C)]
#[derive(Copy, Clone)]
struct UffdioCopy { dst: u64, src: u64, len: u64, mode: u64, copy: u64 }

/// `struct uffdio_zeropage` — 32 bytes.
#[repr(C)]
#[derive(Copy, Clone)]
struct UffdioZeropage { range: UffdioRange, mode: u64, zeropage: u64 }

/// Negative errno in syscall encoding. # C: O(1)
#[inline]
fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Linux `capable(CAP_SYS_PTRACE)` for the running task; false when there is
/// no current task (hosted tests). # C: O(1)
fn cur_cap_sys_ptrace() -> bool {
    sched::current().map(|c| super::capable_sys_ptrace(&c)).unwrap_or(false)
}

/// `ioctl(uffd_fd, UFFDIO_*, arg)` — dispatched by `sys_ioctl` when the
/// fd's inode carries the userfaultfd ino tag.
///
/// Linux `userfaultfd_ioctl` initialises `ret = -EINVAL`, so an unrecognised
/// command returns EINVAL (not ENOTTY), and every command except `UFFDIO_API`
/// is refused with EINVAL until the API handshake has run.
/// # C: O(K) for COPY/ZEROPAGE (K = pages), O(1) otherwise
pub fn handle_uffd_ioctl(inode: &vfs::InodeRef, req: u64, arg: u64) -> i64 {
    let ufd = match as_uffd(inode) { Some(u) => u, None => return err(Errno::Enotty) };
    let feats = ufd.features.load(core::sync::atomic::Ordering::Acquire);
    if let Err(e) = policy::check_ioctl_ordering(req, feats) { return err(e); }
    match req {
        UFFDIO_API        => ioc_api(&ufd, arg),
        UFFDIO_REGISTER   => ioc_register(&ufd, arg),
        UFFDIO_UNREGISTER => ioc_unregister(&ufd, arg),
        UFFDIO_COPY       => ioc_copy(&ufd, arg),
        UFFDIO_ZEROPAGE   => ioc_zeropage(&ufd, arg),
        UFFDIO_WAKE       => ioc_wake(&ufd, arg),
        _ => err(Errno::Einval),
    }
}

/// UFFDIO_API: negotiate features and report the fd-level ioctl bitmap.
/// Linux `userfaultfd_api`. On ANY error the reply object is zeroed and
/// written back before the errno is returned (`err_out:`), which is how a
/// monitor distinguishes "old kernel" from "bad argument".
fn ioc_api(ufd: &UfData, arg: u64) -> i64 {
    if let Err(rv) = validate_user_buf_writable(arg, UFFDIO_API_SIZE, 1) { return rv; }
    // SAFETY: arg validated writable for the full 24-byte uffdio_api object.
    let req: UffdioApi = unsafe { core::ptr::read_unaligned(arg as *const UffdioApi) };
    let ctx_features = ufd.features.load(core::sync::atomic::Ordering::Acquire);
    match policy::api_negotiate(req.api, req.features, cur_cap_sys_ptrace(), ctx_features) {
        Ok(reply) => {
            let out = UffdioApi { api: req.api, features: reply.features, ioctls: reply.ioctls };
            // SAFETY: same validated uffdio_api object receives the negotiated reply.
            unsafe { core::ptr::write_unaligned(arg as *mut UffdioApi, out); }
            ufd.features.store(reply.ctx_features, core::sync::atomic::Ordering::Release);
            0
        }
        Err(e) => {
            // SAFETY: same validated uffdio_api object; Linux's err_out memsets it to zero.
            unsafe { core::ptr::write_unaligned(arg as *mut UffdioApi, UffdioApi::default()); }
            err(e)
        }
    }
}

/// UFFDIO_REGISTER: bind this context to every VMA overlapping the range and
/// report the ops guaranteed to work there. Linux `userfaultfd_register`.
fn ioc_register(ufd: &Arc<UfData>, arg: u64) -> i64 {
    if let Err(rv) = validate_user_buf_writable(arg, UFFDIO_REGISTER_SIZE, 1) { return rv; }
    // SAFETY: arg validated writable for the full uffdio_register object.
    let reg: UffdioRegister = unsafe { core::ptr::read_unaligned(arg as *const UffdioRegister) };
    if let Err(e) = policy::check_register_mode(reg.mode) { return err(e); }
    if let Err(e) = policy::validate_range(reg.range.start, reg.range.len) { return err(e); }
    let start = reg.range.start;
    let end   = start + reg.range.len;
    // Linux `if (!mmget_not_zero(mm)) { ret = -ENOMEM; goto out; }`.
    let Some(mm) = ufd.mm() else { return err(Errno::Enomem) };
    if let Err(e) = scan_registerable(&mm, start, end, ufd) { return err(e); }
    ufd.state.lock().ranges.push(RegisteredRange { start, end, mode: reg.mode });
    let ctx: Arc<dyn vmm::UffdContext> = ufd.clone();
    mm.set_uffd_missing(start, end, ctx);
    let ioctls = policy::register_ioctls(reg.mode);
    // SAFETY: arg+24 is the `ioctls` reply slot inside the validated uffdio_register object.
    unsafe { core::ptr::write_unaligned((arg + UFFDIO_REGISTER_IOCTLS_OFF) as *mut u64, ioctls); }
    0
}

/// Linux's per-VMA registration scan over `[start, end)`: at least one VMA
/// must overlap (else EINVAL), and each must pass `policy::check_register_vma`.
/// Holes inside the range are not an error — `for_each_vma_range` simply skips
/// them.
/// # C: O(N_vmas)
fn scan_registerable(mm: &vmm::AddressSpace, start: u64, end: u64, ufd: &Arc<UfData>)
    -> Result<(), Errno> {
    let vmas = mm.uffd_vmas_in(start, end);
    if vmas.is_empty() { return Err(Errno::Einval); }
    for v in &vmas {
        policy::check_register_vma(&RegVma {
            can_userfault: v.anonymous,
            may_write: v.may_write,
            owned_by_other_uffd: v.ctx.as_ref().is_some_and(|c| !ctx_is(c, ufd)),
        })?;
    }
    Ok(())
}

/// Arc identity between a VMA's `dyn UffdContext` and this context. # C: O(1)
fn ctx_is(vma_ctx: &Arc<dyn vmm::UffdContext>, ufd: &Arc<UfData>) -> bool {
    core::ptr::eq(Arc::as_ptr(vma_ctx) as *const u8, Arc::as_ptr(ufd) as *const u8)
}

/// UFFDIO_UNREGISTER: drop the range record + clear the per-VMA hook.
fn ioc_unregister(ufd: &UfData, arg: u64) -> i64 {
    if let Err(rv) = validate_user_buf(arg, UFFDIO_RANGE_SIZE, 1) { return rv; }
    // SAFETY: arg validated readable for the full uffdio_range object.
    let r: UffdioRange = unsafe { core::ptr::read_unaligned(arg as *const UffdioRange) };
    if let Err(e) = policy::validate_range(r.start, r.len) { return err(e); }
    let end = r.start + r.len;
    // Linux `if (!mmget_not_zero(mm)) { ret = -ENOMEM; goto out; }`.
    let Some(mm) = ufd.mm() else { return err(Errno::Enomem) };
    ufd.state.lock().ranges.retain(|reg| !(reg.start == r.start && reg.end == end));
    mm.clear_uffd(r.start, end);
    0
}

/// UFFDIO_WAKE: validate the range, then wake blocked faulters.
/// Linux `userfaultfd_wake` runs `validate_range(ctx->mm, …)` before waking —
/// the previous code read the object and threw it away.
fn ioc_wake(ufd: &UfData, arg: u64) -> i64 {
    if let Err(rv) = validate_user_buf(arg, UFFDIO_RANGE_SIZE, 1) { return rv; }
    // SAFETY: arg validated readable for the full uffdio_range object.
    let r: UffdioRange = unsafe { core::ptr::read_unaligned(arg as *const UffdioRange) };
    if let Err(e) = policy::validate_range(r.start, r.len) { return err(e); }
    ufd.wake_faulters();
    0
}

/// UFFDIO_COPY: fill `[dst, dst+len)` in `ctx->mm` from the monitor's `src`.
/// Linux `userfaultfd_copy` → `mfill_atomic_copy`.
fn ioc_copy(ufd: &UfData, arg: u64) -> i64 {
    if let Err(rv) = validate_user_buf_writable(arg, UFFDIO_COPY_SIZE, 1) { return rv; }
    // SAFETY: arg validated writable for the full uffdio_copy object.
    let c: UffdioCopy = unsafe { core::ptr::read_unaligned(arg as *const UffdioCopy) };
    // Linux validates SRC before DST, and the mode word after both.
    if let Err(e) = policy::validate_unaligned_range(c.src, c.len) { return err(e); }
    if let Err(e) = policy::validate_range(c.dst, c.len) { return err(e); }
    if let Err(e) = policy::check_copy_mode(c.mode) { return err(e); }
    // The source is read through the CALLER's address space (Linux's
    // `copy_from_user` inside `mfill_atomic_pte_copy` runs in `current`'s
    // context even when `ctx->mm` differs), so it is validated against
    // `current` — unlike the destination, which belongs to `ctx->mm`.
    if let Err(rv) = validate_user_buf_readable(c.src, c.len, 1) { return rv; }
    fill(ufd, c.dst, Some(c.src), c.len, c.mode,
         arg + UFFDIO_COPY_COPY_OFF, c.mode & UFFDIO_COPY_MODE_WP != 0)
}

/// UFFDIO_ZEROPAGE: fill `[start, start+len)` in `ctx->mm` with zero pages.
/// Linux `userfaultfd_zeropage` → `mfill_atomic_zeropage`.
fn ioc_zeropage(ufd: &UfData, arg: u64) -> i64 {
    if let Err(rv) = validate_user_buf_writable(arg, UFFDIO_ZEROPAGE_SIZE, 1) { return rv; }
    // SAFETY: arg validated writable for the full uffdio_zeropage object.
    let z: UffdioZeropage = unsafe { core::ptr::read_unaligned(arg as *const UffdioZeropage) };
    if let Err(e) = policy::validate_range(z.range.start, z.range.len) { return err(e); }
    if let Err(e) = policy::check_zeropage_mode(z.mode) { return err(e); }
    fill(ufd, z.range.start, None, z.range.len, z.mode,
         arg + UFFDIO_ZEROPAGE_ZEROPAGE_OFF, false)
}

/// Shared tail of COPY/ZEROPAGE: resolve `ctx->mm`, prove the destination is a
/// uffd-registered VMA, install, then write the byte-count field and encode the
/// return per Linux's protocol.
///
/// The destination ladder is the whole point of this function. Before it, the
/// install ran against `current`'s mm and fell back to `USER|READ|WRITE` page
/// flags when no VMA was found — i.e. any holder of a uffd fd could
/// materialise a writable page at an arbitrary page-aligned user address.
/// # C: O(N_vmas) lookup + O(len/PAGE) install
fn fill(ufd: &UfData, dst: u64, src: Option<u64>, len: u64, mode: u64,
        count_slot: u64, want_wp: bool) -> i64 {
    // Linux `mmget_not_zero(ctx->mm)` … `else return -ESRCH;` — that arm
    // returns WITHOUT touching the reply word, unlike the failures below.
    let Some(mm) = ufd.mm() else { return err(Errno::Esrch) };
    let vma = UserVirtAddr::new(dst).and_then(|v| mm.uffd_vma_at(v));
    let dst_vma = vma.as_ref().map(|v| DstVma {
        end: v.end,
        uffd_registered: v.ctx.is_some(),
        // oxide refuses UFFDIO_REGISTER_MODE_WP, so no VMA can carry VM_UFFD_WP.
        uffd_wp: false,
    });
    // A destination-ladder rejection is `mfill_atomic` returning a negative
    // errno, and Linux's `put_user(ret, &user_uffdio_copy->copy)` runs on that
    // path too — the monitor reads the errno out of the reply word.
    let (installed, fill_err) = match policy::check_dst_vma(dst + len, dst_vma, want_wp) {
        Err(e) => (0, Some(e)),
        Ok(()) => {
            let flags = vma.expect("check_dst_vma rejects a missing VMA").prot.to_page_flags();
            install_pages(mm.root_pa(), dst, src, len, flags)
        }
    };
    let (rv, count) = policy::fill_retval(installed, len, fill_err);
    // SAFETY: count_slot is the trailing reply word inside the uffdio_copy / uffdio_zeropage object already validated writable by the caller.
    unsafe { core::ptr::write_unaligned(count_slot as *mut i64, count); }
    if policy::should_wake(mode, installed) { ufd.wake_faulters(); }
    rv
}
