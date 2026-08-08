// The kernel half: reserve the persistent region out of the boot memory map,
// map it, attach the backend to it, and wire the two producers — the crash
// dumper and the console.
//
// Everything decided here is decided elsewhere: which address (`geometry`),
// how it divides (`geometry`), what a zone holds (`zone`), what a record
// contains (`psinfo`). This file supplies the physical facts and the hooks,
// and is the only part of the crate a hosted test cannot reach.
#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

use boot_info::{BootInfo, BootMemKind, BootMemRegion};

use crate::geometry::{choose_base, round_region_size, UsableRange};
use crate::limits::{DEFAULT_CONSOLE_SIZE, DEFAULT_MEM_SIZE, DEFAULT_RECORD_SIZE};
use crate::psinfo;
use crate::ram::{RamBackend, RamRegion};
use crate::uapi::DumpReason;

/// The reserved region, published by [`reserve`] for [`init`] to map. Zero
/// means no region was reserved, and every path below degrades to "no
/// backend", which is a supported state.
static REGION_PA: AtomicUsize = AtomicUsize::new(0);
static REGION_LEN: AtomicUsize = AtomicUsize::new(0);

fn cmdline_usize(name: &[u8]) -> Option<usize> {
    let v = cmdline::parameter_value(name)?;
    let s = core::str::from_utf8(v).ok()?;
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return usize::from_str_radix(hex, 16).ok();
    }
    s.parse::<usize>().ok()
}

/// Reserve the persistent region from the page allocator.
///
/// MUST run immediately after allocator init and before the first
/// allocation: the reservation removes pages from the free lists, and a page
/// already handed out is silently skipped — which would leave the backend
/// writing into memory something else owns.
///
/// The region is excluded from the allocator rather than allocated from it
/// because its whole purpose is to outlive the kernel that reserved it: an
/// allocation lands wherever the allocator's state puts it, which is not the
/// same place after a reboot.
/// # SAFETY: caller is the boot path, single-CPU, after allocator init and
/// before any allocation from it.
/// # C: O(region length / page size)
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn reserve(info: &BootInfo) {
    let want = round_region_size(
        cmdline_usize(b"ramoops.mem_size").unwrap_or(DEFAULT_MEM_SIZE));
    // SAFETY: the boot-info contract makes `memmap_ptr`/`memmap_count` a
    // valid slice for the duration of the boot path.
    let regions: &[BootMemRegion] = unsafe {
        core::slice::from_raw_parts(info.memmap_ptr, info.memmap_count as usize)
    };
    let mut ranges = alloc::vec::Vec::new();
    for r in regions {
        if r.kind == BootMemKind::Usable { ranges.push(UsableRange { base: r.base_pa, len: r.len }); }
    }
    let pa = match cmdline_usize(b"ramoops.mem_address") {
        Some(a) => a as u64,
        None => match choose_base(&ranges, want as u64) { Some(a) => a, None => return },
    };
    let Some(pmm) = pmm::setup::pmm_static() else { return };
    let pages = (want as u64) / hal::PAGE_SIZE_BYTES;
    if pmm.reserve_early(hal::Pfn(pa / hal::PAGE_SIZE_BYTES), pages).is_err() { return; }
    REGION_PA.store(pa as usize, Ordering::Release);
    REGION_LEN.store(want, Ordering::Release);
}

/// Attach the backend to the reserved region and start recording.
///
/// Runs after the direct map is published, because the region is reached
/// through it. Enumerates whatever the previous boot left behind, registers
/// the backend so a mount can publish it, and hooks the two producers the
/// reference hooks: the crash dumper and the console.
/// # SAFETY: caller is the boot path, after `reserve` and after the direct
/// map offset is known; runs once.
/// # C: O(region length)
/// # Ctx: pre-init, single-CPU
pub unsafe fn init() {
    let pa = REGION_PA.load(Ordering::Acquire);
    let len = REGION_LEN.load(Ordering::Acquire);
    if pa == 0 || len == 0 { return; }
    let hhdm = pmm::user_as::hhdm_offset();
    if hhdm == 0 { return; }
    let va = (hhdm as usize).wrapping_add(pa);
    let record_size = cmdline_usize(b"ramoops.record_size").unwrap_or(DEFAULT_RECORD_SIZE);
    let console_size = cmdline_usize(b"ramoops.console_size").unwrap_or(DEFAULT_CONSOLE_SIZE);
    if let Some(m) = cmdline_usize(b"ramoops.max_reason") {
        psinfo::set_max_reason(m as u8);
    }
    // SAFETY: `pa..pa+len` was removed from the page allocator by `reserve`,
    // so nothing else owns it; the direct map covers every usable physical
    // page, making `va` a mapped writable alias of it for the whole boot.
    let region = unsafe { RamRegion::new(va, len) };
    let (backend, survivors) = RamBackend::attach(region, record_size, console_size);
    // The geometry and the survivor count are the two facts that say whether
    // the region came back intact, and they are the only ones a boot log needs.
    #[cfg(feature = "debug-pstore")] {
        klog::write_raw(backend.describe().as_bytes());
        klog::write_raw(b"pstore: ");
        klog::write_dec_u64(survivors.len() as u64);
        klog::write_raw(b" record(s) survived the last boot\n");
    }
    #[cfg(not(feature = "debug-pstore"))] let _ = survivors.len();
    if !psinfo::register(Arc::clone(&backend)) { return; }
    klog::set_kmsg_dump_hook(dump_hook);
    klog::register_console(console_hook);
}

/// The crash-dump producer. Runs on a kernel that is about to stop, so it
/// allocates nothing beyond the record it composes and never waits.
/// # C: O(captured length)
fn dump_hook(reason: u8) {
    let r = DumpReason::from_raw(reason);
    if !psinfo::should_capture(r, psinfo::max_reason()) { return; }
    // The snapshot lands in the buffer allocated when the backend registered:
    // the crash path neither allocates nor puts the log on the stack, which on
    // a 16 KiB kernel stack is the difference between a record and a scribble
    // over whatever is next to it.
    psinfo::capture_snapshot(r, wall_clock(), |dst| {
        let total = klog::ring_total();
        let start = total.saturating_sub(dst.len());
        let (n, _) = klog::ring_read(start, dst);
        (n, total)
    });
}

/// The console producer: every byte the kernel prints is appended to the
/// console zone, so the previous boot's log is readable after a reboot even
/// when nothing crashed. # C: O(len bytes)
fn console_hook(bytes: &[u8]) {
    if let Some(b) = psinfo::backend() { b.write_console(bytes); }
}

/// Wall clock at capture time, so a record file's modification time is when
/// the crash happened rather than when the next boot mounted it.
fn wall_clock() -> (u64, u32) {
    let ns = timekeeper::realtime_ns();
    (ns / 1_000_000_000, (ns % 1_000_000_000) as u32)
}
