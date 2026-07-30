// 216 remap_file_pages — deprecated nonlinear-mapping call, kept alive by
// Linux as an EMULATION over mmap (docs/53 §0).
//
// `mm/mmap.c` SYSCALL_DEFINE5(remap_file_pages) no longer builds a nonlinear
// VMA: after validating the arguments it re-maps the SAME file over the SAME
// address with `MAP_SHARED | MAP_FIXED | MAP_POPULATE` (plus MAP_LOCKED when
// the VMA was VM_LOCKED, and the caller's MAP_NONBLOCK), taking the protection
// from the existing VMA and the offset from the caller's `pgoff`. Anything the
// request cannot express that way is EINVAL — most notably a nonzero `prot`,
// which the old interface accepted and the emulation refuses.
//
// The argument ladder is `crate::remap_policy` (hosted-tested); this file does
// the VMA lookup and the re-mmap (docs/53 shim).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::remap_policy::remap_check;

const PAGE: u64 = hal::PAGE_SIZE_BYTES;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Linux rebuilds `prot` from the target VMA's `VM_READ/WRITE/EXEC` — the
/// caller is not allowed to supply one — so the re-mmap reproduces exactly the
/// protection the mapping already had. # C: O(1)
fn prot_bits(p: vmm::VmaProt) -> u64 {
    use pmm::mmap_flags::{PROT_EXEC, PROT_READ, PROT_WRITE};
    let mut out = 0;
    if p.contains(vmm::VmaProt::READ)  { out |= PROT_READ; }
    if p.contains(vmm::VmaProt::WRITE) { out |= PROT_WRITE; }
    if p.contains(vmm::VmaProt::EXEC)  { out |= PROT_EXEC; }
    out
}

/// `sys_remap_file_pages(start, size, prot, pgoff, flags)` — slot 216.
/// Errors: EINVAL (nonzero `prot`, empty/wrapping range, wrapping `pgoff`, no
/// VMA at `start`, a VMA that is not MAP_SHARED file-backed, or a request
/// spanning a hole / a differently-backed neighbour), plus whatever the
/// underlying mmap reports.
/// # C: O(N_vmas + size/PAGE)
pub fn sys_remap_file_pages(args: &SyscallArgs) -> i64 {
    use pmm::mmap_flags::{MAP_FIXED, MAP_LOCKED, MAP_NONBLOCK, MAP_POPULATE, MAP_SHARED};

    let range = match remap_check(args.a2, args.a0, args.a1, args.a3, PAGE) {
        Ok(r)  => r,
        Err(e) => return err(e),
    };
    let pgoff = args.a3;
    let user_flags = args.a4;

    let cur = match sched::live::current() { Some(c) => c, None => return err(Errno::Einval) };
    // SAFETY: mm slot single-mutator per `13§5`; running task on this CPU; Arc clone.
    let mm = match unsafe { cur.mm_ref() } { Some(m) => m.clone(), None => return err(Errno::Einval) };

    let start_uva = match hal::UserVirtAddr::new(range.start) { Some(u) => u, None => return err(Errno::Einval) };
    // Linux `vma_lookup(mm, start)`: the VMA CONTAINING start, not the next one.
    let vma = match mm.find_vma(start_uva) { Some(v) => v, None => return err(Errno::Einval) };
    if !vma.flags.contains(vmm::VmaFlags::SHARED) { return err(Errno::Einval); }
    // `get_file(vma->vm_file)` in Linux; a shared mapping with no file backing
    // has nothing to re-map at a new offset.
    let backing = match &vma.backing {
        vmm::VmaBacking::File { backing, .. } => backing.clone(),
        _ => return err(Errno::Einval),
    };

    // Linux walks the following VMAs when the request runs past this one, and
    // requires them contiguous, same-file and same-flags; a hole or a foreign
    // neighbour is EINVAL rather than a partial remap.
    let end = range.start + range.size;
    if end > vma.end.as_u64() {
        let mut covered = vma.end.as_u64();
        for next in mm.snapshot_vmas().iter().filter(|v| v.start.as_u64() >= vma.end.as_u64()) {
            if next.start.as_u64() != covered { return err(Errno::Einval); }
            if next.flags != vma.flags { return err(Errno::Einval); }
            match (&next.backing, &vma.backing) {
                (vmm::VmaBacking::File { backing: b, .. }, vmm::VmaBacking::File { backing: a, .. })
                    if alloc::sync::Arc::ptr_eq(a, b) => {}
                _ => return err(Errno::Einval),
            }
            covered = next.end.as_u64();
            if covered >= end { break; }
        }
        if covered < end { return err(Errno::Einval); }
    }

    // `flags &= MAP_NONBLOCK; flags |= MAP_SHARED|MAP_FIXED|MAP_POPULATE;`
    // then MAP_LOCKED for a VM_LOCKED VMA — the caller's other flags are
    // DISCARDED, so a stray MAP_PRIVATE cannot turn a shared mapping private.
    let mut flags = (user_flags & MAP_NONBLOCK) | MAP_SHARED | MAP_FIXED | MAP_POPULATE;
    if vma.flags.contains(vmm::VmaFlags::LOCKED) { flags |= MAP_LOCKED; }

    let file_off = match pgoff.checked_mul(PAGE) { Some(o) => o, None => return err(Errno::Einval) };
    let mut final_prot = vma.prot;
    if final_prot.contains(vmm::VmaProt::READ)
        && vma.may_prot.contains(vmm::VmaProt::EXEC)
        && sched::personality::read_implies_exec(&cur)
    {
        final_prot |= vmm::VmaProt::EXEC;
    }
    match pmm::user_as::glue_mmap(range.start, range.size, prot_bits(final_prot), flags, -1,
                                  file_off, Some(backing), None, None, vma.may_prot) {
        // Linux discards the address `do_mmap` returns and reports 0.
        Ok(_)   => 0,
        Err(rv) => rv,
    }
}
