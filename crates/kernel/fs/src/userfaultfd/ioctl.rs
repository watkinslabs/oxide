// UFFDIO_* ioctl dispatch for userfaultfd(2). ABI structs + the real
// COPY/ZEROPAGE page-install path (PMM frame alloc + map into the
// faulting AS), REGISTER/UNREGISTER wiring the mm-vmm uffd hook, and
// WAKE. See `mod.rs` header for the MISSING-mode flow.

use alloc::sync::Arc;

use syscall::errno::Errno;

#[cfg(target_os = "oxide-kernel")]
use hal::{MmuOps, Pa, PageFlags, PageSize, Va};

use super::{as_uffd, RegisteredRange, UfData, UFFD_API_FEATURE_SET};

/// 4 KiB page granule for the COPY/ZEROPAGE install loop.
const PAGE: u64 = hal::PAGE_SIZE_BYTES;

// ioctl request numbers (Linux `linux/userfaultfd.h`).
const UFFDIO_API:        u64 = 0xc018_aa3f;
const UFFDIO_REGISTER:   u64 = 0xc020_aa00;
const UFFDIO_UNREGISTER: u64 = 0x8010_aa01;
const UFFDIO_WAKE:       u64 = 0x8010_aa02;
const UFFDIO_COPY:       u64 = 0xc028_aa03;
const UFFDIO_ZEROPAGE:   u64 = 0xc020_aa04;

/// `uffdio_register.mode` bit — intercept MISSING (NotPresent) faults.
const UFFDIO_REGISTER_MODE_MISSING: u64 = 1 << 0;
/// `uffdio_register.mode` bit — write-protect faults (recorded only; the
/// WP fault intercept is not yet wired — see below).
const UFFDIO_REGISTER_MODE_WP:      u64 = 1 << 1;

/// `uffdio_register.ioctls` reply bitmap — the ops valid on the range.
const UFFD_API_RANGE_IOCTLS: u64 =
    (1u64 << 1/*WAKE*/) | (1u64 << 2/*COPY*/) | (1u64 << 3/*ZEROPAGE*/);

/// `struct uffdio_api` — 16 bytes.
#[repr(C)]
#[derive(Copy, Clone, Default)]
struct UffdioApi { api: u64, features: u64 }

#[repr(C)]
#[derive(Copy, Clone)]
struct UffdioRange { start: u64, len: u64 }

/// `struct uffdio_register` — 32 bytes.
#[repr(C)]
struct UffdioRegister { range: UffdioRange, mode: u64, ioctls: u64 }

/// `struct uffdio_copy` — 40 bytes.
#[repr(C)]
struct UffdioCopy { dst: u64, src: u64, len: u64, mode: u64, copy: u64 }

/// `struct uffdio_zeropage` — 32 bytes.
#[repr(C)]
struct UffdioZeropage { range: UffdioRange, mode: u64, zeropage: u64 }

/// The current task's mm (faulting AS == monitor's mm in the common
/// single-process case). `None` if there is no current mm (e.g. hosted).
/// # C: O(1)
fn current_mm() -> Option<Arc<vmm::AddressSpace>> {
    let cur = sched::current()?;
    // SAFETY: running task on this CPU; preempt-off; single-mutator mm slot per 13§5; we only clone the Arc.
    let mm = unsafe { cur.mm_ref() }?;
    Some(mm.clone())
}

/// Page flags for a COPY/ZEROPAGE install: the containing VMA's prot with
/// the USER bit, falling back to user RW when no VMA is found (Linux
/// installs per the VMA protection).
/// # C: O(log N)
#[cfg(target_os = "oxide-kernel")]
fn install_flags(mm: &vmm::AddressSpace, page: u64) -> PageFlags {
    match hal::UserVirtAddr::new(page).and_then(|v| mm.find_vma(v)) {
        Some(v) => v.prot.to_page_flags(),
        None    => PageFlags::USER | PageFlags::READ | PageFlags::WRITE,
    }
}

/// Flush the just-installed VA on the local CPU so the faulter's retry
/// walks the new leaf. # C: O(1)
#[cfg(target_os = "oxide-kernel")]
#[inline]
fn flush_local(va: u64) {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: privileged local TLB invalidation of a freshly-mapped user VA; legal at CPL=0.
    unsafe { hal_x86_64::flush_local_va(va); }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: tlbi of a freshly-mapped user VA so the faulter's retry walks the new PTE; privileged but legal at EL1.
    unsafe { <hal_aarch64::mmu_ops::ArmMmu as hal::MmuOps>::flush_va(Va(va)); }
}

/// Map one freshly-filled frame `pa` at user page `dst` in `root`, then
/// flush the local TLB entry.
/// # C: O(1)
/// # SAFETY: `pa` is a PMM frame owned by the caller and fully filled;
/// `dst` is a page-aligned user VA in the AS rooted at `root`.
#[cfg(target_os = "oxide-kernel")]
unsafe fn map_page(root: u64, dst: u64, pa: u64, flags: PageFlags) {
    // SAFETY: caller guarantees pa is an owned filled frame and dst is a page-aligned user VA in `root`; map_at installs the leaf, allocating intermediate tables from the PMM.
    unsafe { let _ = <ArchMmu as MmuOps>::map_at(root, Va(dst), Pa(pa), flags, PageSize::P4K); }
    flush_local(dst);
}

/// Install `[dst0, dst0+len)` from monitor source `src0` (COPY) or from
/// zeroed frames (`src0 == None`, ZEROPAGE) into `mm`. Returns the byte
/// count actually installed (short only on frame-alloc exhaustion).
/// # C: O(len/PAGE)
#[cfg(target_os = "oxide-kernel")]
fn install_pages(mm: &vmm::AddressSpace, dst0: u64, src0: Option<u64>, len: u64) -> u64 {
    let root = mm.root_pa();
    let hhdm = pmm::user_as::hhdm_offset();
    let mut done = 0u64;
    while done < len {
        let dst = dst0 + done;
        let pa = match pmm::setup::alloc_one_frame() { Some(p) => p, None => break };
        // SAFETY: pa is a fresh PMM frame; its HHDM mirror at hhdm+pa is kernel-writable; a COPY src is a validated user VA in the active AS (a not-present src demand-faults normally); PAGE bytes fit the frame.
        unsafe {
            let frame = (hhdm + pa) as *mut u8;
            match src0 {
                Some(s) => core::ptr::copy_nonoverlapping((s + done) as *const u8, frame, PAGE as usize),
                None    => core::ptr::write_bytes(frame, 0, PAGE as usize),
            }
            map_page(root, dst, pa, install_flags(mm, dst));
        }
        done += PAGE;
    }
    done
}

/// Hosted stub: the live-AS frame-install path needs the kernel PMM +
/// arch MMU, so hosted builds never install (COPY/ZEROPAGE are boot-
/// verified, not hosted-tested).
#[cfg(not(target_os = "oxide-kernel"))]
fn install_pages(_mm: &vmm::AddressSpace, _dst0: u64, _src0: Option<u64>, _len: u64) -> u64 { 0 }

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
use hal_x86_64::mmu_ops::X86Mmu as ArchMmu;
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
use hal_aarch64::mmu_ops::ArmMmu as ArchMmu;

/// `ioctl(uffd_fd, UFFDIO_*, arg)` — dispatched by `sys_ioctl` when the
/// fd's inode carries the userfaultfd ino tag.
/// # C: O(K) for COPY/ZEROPAGE (K = pages), O(1) otherwise
pub fn handle_uffd_ioctl(inode: &vfs::InodeRef, req: u64, arg: u64) -> i64 {
    let ufd = match as_uffd(inode) { Some(u) => u, None => return -(Errno::Enotty.as_i32() as i64) };
    if arg == 0 || arg >= hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    match req {
        UFFDIO_API        => ioc_api(&ufd, arg),
        UFFDIO_REGISTER   => ioc_register(&ufd, arg),
        UFFDIO_UNREGISTER => ioc_unregister(&ufd, arg),
        UFFDIO_COPY       => ioc_copy(&ufd, arg),
        UFFDIO_ZEROPAGE   => ioc_zeropage(&ufd, arg),
        UFFDIO_WAKE       => { ufd.wake_faulters(); 0 }
        _ => -(Errno::Enotty.as_i32() as i64),
    }
}

/// UFFDIO_API: negotiate features (we advertise none).
fn ioc_api(ufd: &UfData, arg: u64) -> i64 {
    // SAFETY: arg validated < USER_VA_END; UffdioApi is 16 bytes; CPL=0 read through the caller's active AS.
    let mut api: UffdioApi = unsafe { core::ptr::read_volatile(arg as *const UffdioApi) };
    api.features = UFFD_API_FEATURE_SET;
    // SAFETY: same 16-byte range; CPL=0 write-back of the negotiated fields.
    unsafe { core::ptr::write_volatile(arg as *mut UffdioApi, api); }
    ufd.state.lock().api_set = true;
    0
}

/// UFFDIO_REGISTER: record the range + (for MISSING) install the mm-vmm
/// uffd fault hook over it. WP is recorded only (intercept not wired).
fn ioc_register(ufd: &Arc<UfData>, arg: u64) -> i64 {
    // SAFETY: arg validated < USER_VA_END; UffdioRegister is 32 bytes; CPL=0 read.
    let mut reg: UffdioRegister = unsafe { core::ptr::read_volatile(arg as *const UffdioRegister) };
    let start = reg.range.start;
    let end   = start.saturating_add(reg.range.len);
    if start == 0 || end <= start || end >= hal::USER_VA_END
       || (start & (PAGE - 1)) != 0 || (reg.range.len & (PAGE - 1)) != 0
       || (reg.mode & (UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_WP)) == 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    ufd.state.lock().ranges.push(RegisteredRange { start, end, mode: reg.mode });
    // MISSING: bind this uffd ctx to every VMA in the range so a
    // NotPresent fault routes here. WP-only registration is recorded
    // (so UNREGISTER balances) but installs NO intercept — WP-fault
    // interception is not yet implemented; we do not fake it.
    if (reg.mode & UFFDIO_REGISTER_MODE_MISSING) != 0 {
        if let Some(mm) = current_mm() {
            let ctx: Arc<dyn vmm::UffdContext> = ufd.clone();
            mm.set_uffd_missing(start, end, ctx);
        }
    }
    reg.ioctls = UFFD_API_RANGE_IOCTLS;
    // SAFETY: arg+24 is the `ioctls` field within the 32-byte struct; aligned u64 write-back.
    unsafe { core::ptr::write_volatile((arg + 24) as *mut u64, reg.ioctls); }
    0
}

/// UFFDIO_UNREGISTER: drop the range record + clear the mm-vmm hook.
fn ioc_unregister(ufd: &UfData, arg: u64) -> i64 {
    // SAFETY: arg validated < USER_VA_END; UffdioRange is 16 bytes; CPL=0 read.
    let r: UffdioRange = unsafe { core::ptr::read_volatile(arg as *const UffdioRange) };
    let end = r.start.saturating_add(r.len);
    ufd.state.lock().ranges.retain(|reg| !(reg.start == r.start && reg.end == end));
    if let Some(mm) = current_mm() { mm.clear_uffd(r.start, end); }
    0
}

/// UFFDIO_COPY: allocate frames, copy the monitor's `src` bytes in, map
/// them at `dst` in the faulting AS, then wake blocked faulters.
fn ioc_copy(ufd: &UfData, arg: u64) -> i64 {
    // SAFETY: arg validated < USER_VA_END; UffdioCopy is 40 bytes; CPL=0 read.
    let mut c: UffdioCopy = unsafe { core::ptr::read_volatile(arg as *const UffdioCopy) };
    if c.dst == 0 || c.src == 0 || c.len == 0
       || (c.dst & (PAGE - 1)) != 0 || (c.len & (PAGE - 1)) != 0
       || c.dst.checked_add(c.len).map_or(true, |e| e >= hal::USER_VA_END)
       || c.src.checked_add(c.len).map_or(true, |e| e >= hal::USER_VA_END) {
        return -(Errno::Efault.as_i32() as i64);
    }
    let mm = match current_mm() { Some(m) => m, None => return -(Errno::Efault.as_i32() as i64) };
    let done = install_pages(&mm, c.dst, Some(c.src), c.len);
    ufd.wake_faulters();
    c.copy = done;
    // SAFETY: arg+32 is the `copy` output field within the 40-byte struct; aligned u64 write-back.
    unsafe { core::ptr::write_volatile((arg + 32) as *mut u64, c.copy); }
    if done == c.len { 0 } else { -(Errno::Enomem.as_i32() as i64) }
}

/// UFFDIO_ZEROPAGE: install freshly-zeroed frames at the range, then wake.
fn ioc_zeropage(ufd: &UfData, arg: u64) -> i64 {
    // SAFETY: arg validated < USER_VA_END; UffdioZeropage is 32 bytes; CPL=0 read.
    let mut z: UffdioZeropage = unsafe { core::ptr::read_volatile(arg as *const UffdioZeropage) };
    let (start, len) = (z.range.start, z.range.len);
    if start == 0 || len == 0
       || (start & (PAGE - 1)) != 0 || (len & (PAGE - 1)) != 0
       || start.checked_add(len).map_or(true, |e| e >= hal::USER_VA_END) {
        return -(Errno::Efault.as_i32() as i64);
    }
    let mm = match current_mm() { Some(m) => m, None => return -(Errno::Efault.as_i32() as i64) };
    let done = install_pages(&mm, start, None, len);
    ufd.wake_faulters();
    z.zeropage = done;
    // SAFETY: arg+24 is the `zeropage` output field within the 32-byte struct; aligned u64 write-back.
    unsafe { core::ptr::write_volatile((arg + 24) as *mut u64, z.zeropage); }
    if done == len { 0 } else { -(Errno::Enomem.as_i32() as i64) }
}
