// The two image slots, the lock that serialises them, and the load-disable
// latch.
//
// One image may be staged for `reboot(LINUX_REBOOT_CMD_KEXEC)` and one for the
// panic path, and both `kexec_load` and `kexec_file_load` install into the same
// pair — a second registry beside this one is exactly the split source of truth
// that would let `reboot` boot an image a later load had already replaced.

extern crate alloc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use sync::{Spinlock, TaskList as KexecLockClass};

use crate::frames::Frames;
use crate::image::{KImage, SegmentSource};
use crate::stage::{stage_image, Limits};
use crate::uapi::*;
use crate::validate::{Error, KResult};

/// The staged images.
struct Slots {
    normal: Option<KImage>,
    crash: Option<KImage>,
}

static SLOTS: Spinlock<Slots, KexecLockClass> = Spinlock::new(Slots { normal: None, crash: None });

/// Linux's `__kexec_lock`: a plain try-lock, never a blocking one. A caller
/// that would have to wait gets EBUSY instead, because the holder may be a
/// kexec reboot already in progress — blocking behind it means blocking
/// forever, inside a syscall, with the machine on its way down.
static KEXEC_LOCK: AtomicBool = AtomicBool::new(false);

/// `kexec_load_disabled`: once set, no image may be loaded for the rest of this
/// boot. One-way by design — a machine that has decided not to trust a new
/// kernel must not be talked back into it.
static LOAD_DISABLED: AtomicBool = AtomicBool::new(false);

/// # C: O(1)
pub fn load_disabled() -> bool { LOAD_DISABLED.load(Ordering::Relaxed) }

/// Latch `kexec_load_disabled`. Clearing it is not offered, because the
/// reference's sysctl accepts 1 and refuses 0.
/// # C: O(1)
pub fn disable_load() { LOAD_DISABLED.store(true, Ordering::Relaxed); }

/// `kexec_load_permitted`: `CAP_SYS_BOOT` AND the load-disable latch. Callers
/// pass the capability decision because credentials live in `sched`.
/// # C: O(1)
pub fn load_permitted(has_cap_sys_boot: bool) -> bool { has_cap_sys_boot && !load_disabled() }

/// Run `op` under the kexec lock, or report EBUSY without running it.
/// # C: O(op); # Lk: KEXEC_LOCK
pub fn with_kexec_lock<T>(op: impl FnOnce() -> KResult<T>) -> KResult<T> {
    if KEXEC_LOCK.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
        return Err(Error::Busy);
    }
    let r = op();
    KEXEC_LOCK.store(false, Ordering::Release);
    r
}

/// True while an image is staged for `reboot(LINUX_REBOOT_CMD_KEXEC)`.
/// Reported by `/sys/kernel/kexec_loaded`.
/// # C: O(1); # Lk: SLOTS
pub fn kexec_loaded() -> bool { SLOTS.lock().normal.is_some() }

/// True while a crash image is staged. `/sys/kernel/kexec_crash_loaded`.
/// # C: O(1); # Lk: SLOTS
pub fn kexec_crash_loaded() -> bool { SLOTS.lock().crash.is_some() }

/// Empty one slot and return its pages. The image is taken OUT of the slot
/// before it is freed, so nothing can observe a half-freed image.
/// # C: O(N_pages); # Lk: SLOTS
pub fn drop_image<F: Frames>(f: &mut F, crash: bool) {
    let mut old = { let mut s = SLOTS.lock(); if crash { s.crash.take() } else { s.normal.take() } };
    if let Some(img) = old.as_mut() { img.free(f); }
}

/// Stage `segments` and install the result, freeing whatever the slot held.
/// The caller holds the kexec lock.
/// # C: O(total memsz); # Lk: SLOTS
pub fn install_staged<F: Frames, S: SegmentSource>(
    f: &mut F, entry: u64, segments: Vec<KexecSegment>, flags: u64, limits: Limits, src: &S,
    boot_arg: u64,
) -> KResult<()> {
    let crash = flags & KEXEC_ON_CRASH != 0;
    // A crash image is staged into the reserved region the CURRENT crash image
    // occupies, so the old one is freed BEFORE the new one is written — after
    // would corrupt the image just built.
    if crash { drop_image(f, true); }
    let mut image = stage_image(f, entry, segments, flags, limits, src)?;
    // Set after staging rather than threaded through it: the boot argument is
    // a value the arch trampoline reads at jump time and nothing in the
    // staging algorithm consults, so making every staging test state one would
    // add a parameter that cannot affect what those tests check.
    image.boot_arg = boot_arg;
    let mut old = {
        let mut s = SLOTS.lock();
        if crash { s.crash.replace(image) } else { s.normal.replace(image) }
    };
    if let Some(img) = old.as_mut() { img.free(f); }
    Ok(())
}

/// `do_kexec_load`.
///
/// `nr_segments == 0` is the unload: the slot is emptied and its pages
/// returned, and that is the ONLY path by which a load frees an image without
/// building one. It succeeds whether or not an image was loaded.
/// # C: O(total memsz); # Lk: KEXEC_LOCK, SLOTS
pub fn do_kexec_load<F: Frames, S: SegmentSource>(
    f: &mut F,
    entry: u64,
    segments: Vec<KexecSegment>,
    flags: u64,
    limits: Limits,
    src: &S,
) -> KResult<()> {
    with_kexec_lock(|| {
        if segments.is_empty() {
            drop_image(f, flags & KEXEC_ON_CRASH != 0);
            return Ok(());
        }
        // `kexec_load(2)` carries no boot argument: see `KImage::boot_arg`.
        install_staged(f, entry, segments, flags, limits, src, 0)
    })
}

/// `kernel_kexec()`, reached from `reboot(LINUX_REBOOT_CMD_KEXEC)`.
///
/// Order: the kexec lock, then "is an image loaded", then the machine step.
/// EBUSY before EINVAL, because a caller racing a load has established nothing
/// about the slot's contents.
/// # C: O(image size); # Lk: KEXEC_LOCK, SLOTS
pub fn kernel_kexec() -> KResult<()> {
    with_kexec_lock(|| {
        let s = SLOTS.lock();
        match s.normal.as_ref() {
            // Nothing staged: the reference's `-EINVAL`, and the reason
            // `systemctl kexec` falls back to a normal reboot.
            None => Err(Error::Inval),
            // `kernel_restart_prepare("kexec reboot")`: every driver's
            // shutdown method runs BEFORE the relocation, because a device
            // still mastering the bus writes into the new kernel's memory
            // after the copy has finished and nothing is left to notice.
            Some(img) => {
                // The log snapshot goes out BEFORE the drivers stop, because a
                // dumper whose backend rides on a device has nothing left to
                // write to once they have. Same order, same reason, as the
                // terminal reboot path.
                klog::kmsg_dump(klog::kmsg_dump::REASON_SHUTDOWN);
                crate::machine::shutdown_devices();
                crate::machine::kexec(img)
            }
        }
    })
}

/// Reset every piece of process-global kexec state: both image slots (freeing
/// their pages), the kexec lock, and the `kexec_load_disabled` latch.
///
/// Covering ALL of it is the point. A reset that emptied only the slots would
/// leave the latch set from a previous case, so a later `load_permitted` would
/// answer false for a reason its own test never established — the half-reset
/// failure this repo has already paid for once. The lock is included because a
/// test that panics mid-`with_kexec_lock` never releases it, and every later
/// case would then see EBUSY and blame its own code.
/// # C: O(N_pages)
#[cfg(test)]
pub fn clear_for_tests<F: Frames>(f: &mut F) {
    let mut old = { let mut s = SLOTS.lock(); (s.normal.take(), s.crash.take()) };
    if let Some(img) = old.0.as_mut() { img.free(f); }
    if let Some(img) = old.1.as_mut() { img.free(f); }
    KEXEC_LOCK.store(false, Ordering::Release);
    LOAD_DISABLED.store(false, Ordering::Relaxed);
}
