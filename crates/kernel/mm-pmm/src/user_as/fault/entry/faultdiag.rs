//! x86 fault diagnostics kept out of the entry dispatch's stack-sensitive path.

use core::sync::atomic::{AtomicBool, Ordering};

use super::super::{PAGE_BYTES, PAGE_MASK};

const PLT_JMP_INDIRECT: [u8; 2] = [0xff, 0x25];
static FIRST_MISSING_VMA_SNAPSHOT: AtomicBool = AtomicBool::new(false);

/// Claim the single allocation-free missing-VMA snapshot. # C: O(1)
pub(super) fn claim_first_missing_vma() -> bool {
    !FIRST_MISSING_VMA_SNAPSHOT.swap(true, Ordering::AcqRel)
}

/// Decode an x86-64 RIP-relative indirect PLT jump. # C: O(1)
fn plt_got_slot(rip: u64, insn: [u8; 6]) -> Option<u64> {
    if insn[..2] != PLT_JMP_INDIRECT { return None; }
    let disp = i32::from_le_bytes([insn[2], insn[3], insn[4], insn[5]]) as i64;
    rip.checked_add(insn.len() as u64)?.checked_add_signed(disp)
}

/// Log the faulting PLT/GOT state without reading user virtual memory. # C: O(walk depth)
pub(super) fn trace_plt_got(root: u64, rip: u64, hhdm: u64) {
    use hal::pt_walker::translate_4k_at_root;

    // SAFETY: `root` is the faulting address space's page-table root supplied by
    // the fault entry and still installed, and `hhdm` maps all managed RAM, so
    // the walker only dereferences HHDM views of live table frames.
    let code = unsafe {
        translate_4k_at_root::<hal_x86_64::vmm::PtWalkerX86>(root, rip, hhdm)
    };
    let Some(code) = code else {
        klog::write_raw(b" [PLT-GOT] code-unmapped");
        return;
    };
    let code_pa = code.0 & !PAGE_MASK;
    let off = (rip & PAGE_MASK) as usize;
    if off + 6 > PAGE_BYTES as usize {
        klog::write_raw(b" [PLT-GOT] code-page-end");
        return;
    }
    // SAFETY: explicit-root translation proved this instruction page present;
    // HHDM maps managed RAM and this reads six in-page instruction bytes.
    let insn = unsafe { core::ptr::read((hhdm + code_pa + off as u64) as *const [u8; 6]) };
    let Some(slot) = plt_got_slot(rip, insn) else {
        klog::write_raw(b" [PLT-GOT] opcode=");
        klog::write_hex_u64(insn[0] as u64);
        klog::write_raw(b":");
        klog::write_hex_u64(insn[1] as u64);
        klog::write_raw(b" code-pa="); klog::write_hex_u64(code_pa);
        klog::write_raw(b" rc="); klog::write_dec_u64(crate::setup::frame_refcount(code_pa) as u64);
        klog::write_raw(b" mc="); klog::write_dec_u64(crate::setup::frame_mapcount(code_pa) as u64);
        klog::write_raw(b" leaf="); klog::write_hex_u64(code.1);
        return;
    };
    // SAFETY: same still-installed `root` and HHDM as the code-page walk above;
    // `slot` is a GOT address decoded from the instruction, and an unmapped or
    // bogus value simply makes the walk return None.
    let got = unsafe {
        translate_4k_at_root::<hal_x86_64::vmm::PtWalkerX86>(root, slot, hhdm)
    };
    let Some((got_pa, leaf)) = got else {
        klog::write_raw(b" [PLT-GOT] slot-unmapped="); klog::write_hex_u64(slot);
        return;
    };
    let page = got_pa & !PAGE_MASK;
    let word = hhdm + page + (slot & PAGE_MASK);
    // SAFETY: explicit-root translation proved the aligned GOT word's page
    // present; x86-64 PLT slots are eight-byte aligned within that page.
    let value = unsafe { core::ptr::read_volatile(word as *const u64) };
    klog::write_raw(b" [PLT-GOT] slot="); klog::write_hex_u64(slot);
    klog::write_raw(b" value="); klog::write_hex_u64(value);
    klog::write_raw(b" pa="); klog::write_hex_u64(page);
    klog::write_raw(b" rc="); klog::write_dec_u64(crate::setup::frame_refcount(page) as u64);
    klog::write_raw(b" mc="); klog::write_dec_u64(crate::setup::frame_mapcount(page) as u64);
    klog::write_raw(b" leaf="); klog::write_hex_u64(leaf);
}

/// Decode the Wine x86-64 relay call site immediately before a fault. # C: O(1)
pub(super) fn trace_relay(root: u64, rip: u64, rcx: u64, rsp: u64, hhdm: u64) {
    use hal::pt_walker::translate_4k_at_root;

    let Some(previous) = rip.checked_sub(7) else { return; };
    let Some((pa, _)) = (unsafe {
        // SAFETY: `root` is the faulting address space root and `hhdm` maps the
        // live page-table frames used to translate this user instruction.
        translate_4k_at_root::<hal_x86_64::vmm::PtWalkerX86>(root, previous, hhdm)
    }) else { return; };
    let offset = (previous & PAGE_MASK) as usize;
    if offset + 7 > PAGE_BYTES as usize { return; }
    // SAFETY: explicit-root translation proved the complete seven-byte
    // instruction range present in managed RAM; this only reads diagnostics.
    let bytes = unsafe { core::ptr::read((hhdm + (pa & !PAGE_MASK) + offset as u64) as *const [u8; 7]) };
    if bytes[..3] != [0x48, 0x8d, 0x0d] { return; }
    let displacement = i32::from_le_bytes([bytes[3], bytes[4], bytes[5], bytes[6]]) as i64;
    let Some(expected) = rip.checked_add_signed(displacement) else { return; };
    klog::write_raw(b" [WINDOWS-PE-RELAY-SITE] rip=");
    klog::write_hex_u64(rip);
    klog::write_raw(b" expected_rcx=");
    klog::write_hex_u64(expected);
    klog::write_raw(b" actual_rcx=");
    klog::write_hex_u64(rcx);
    klog::write_raw(b" disp=");
    klog::write_hex_u64(displacement as u64);
    if let Some(slot) = expected.checked_add(8) {
        if let Some(slot_va) = hal::UserVirtAddr::new(slot) {
            if let Some(task) = sched::live::current() {
                if let Some(mm) = unsafe { task.mm_ref() } {
                    if let Some(vma) = mm.find_vma(slot_va) {
                    klog::write_raw(b" descriptor_vma=");
                    klog::write_hex_u64(vma.start.as_u64());
                    klog::write_raw(b"-");
                    klog::write_hex_u64(vma.end.as_u64());
                    } else {
                        klog::write_raw(b" descriptor_vma=none");
                    }
                }
            }
        }
        if let Some((slot_pa, _)) = unsafe {
            // SAFETY: the explicit-root walk validates the descriptor slot's
            // page before this diagnostic-only volatile read.
            translate_4k_at_root::<hal_x86_64::vmm::PtWalkerX86>(root, slot, hhdm)
        } {
            let value = unsafe {
                // SAFETY: the slot page was just translated in this address
                // space; this reads only the eight-byte relay pointer.
                core::ptr::read_volatile((hhdm + (slot_pa & !PAGE_MASK) + (slot & PAGE_MASK)) as *const u64)
            };
            klog::write_raw(b" descriptor_slot=");
            klog::write_hex_u64(value);
        } else {
            klog::write_raw(b" descriptor_slot=unmapped");
        }
    }
    let Some((stack_pa, _)) = (unsafe {
        // SAFETY: the same faulting address space root translates the user
        // stack containing the interrupted call's return address.
        translate_4k_at_root::<hal_x86_64::vmm::PtWalkerX86>(root, rsp, hhdm)
    }) else { return; };
    // SAFETY: explicit-root translation proved the return-address word's page
    // present; this reads one diagnostic word from the interrupted stack.
    let return_address = unsafe { core::ptr::read_volatile((hhdm + (stack_pa & !PAGE_MASK) + (rsp & PAGE_MASK)) as *const u64) };
    klog::write_raw(b" return=");
    klog::write_hex_u64(return_address);
}

/// Record the bytes at a PE instruction fault before the page resolver can
/// change the mapping. This distinguishes a bad materialized image from a
/// retry that resumes with the wrong saved RIP. # C: O(walk depth)
pub(super) fn trace_code_window(root: u64, rip: u64, hhdm: u64) {
    use hal::pt_walker::translate_4k_at_root;

    let page = rip & !PAGE_MASK;
    let Some((pa, _)) = (unsafe {
        // SAFETY: `root` is the faulting address space root and `hhdm` maps
        // the page-table frames used for this diagnostic read.
        translate_4k_at_root::<hal_x86_64::vmm::PtWalkerX86>(root, page, hhdm)
    }) else {
        klog::write_raw(b" [WINDOWS-PE-CODE] unmapped rip=");
        klog::write_hex_u64(rip);
        return;
    };
    let offset = (rip & PAGE_MASK) as usize;
    if offset >= PAGE_BYTES as usize || offset + 16 > PAGE_BYTES as usize { return; }
    // SAFETY: translation proved the complete in-page byte window present.
    let bytes = unsafe {
        core::ptr::read((hhdm + (pa & !PAGE_MASK) + offset as u64) as *const [u8; 16])
    };
    klog::write_raw(b" [WINDOWS-PE-CODE] rip=");
    klog::write_hex_u64(rip);
    klog::write_raw(b" bytes=");
    for byte in bytes { klog::write_hex_u64(byte as u64); }
    klog::write_raw(b"\n");
}
