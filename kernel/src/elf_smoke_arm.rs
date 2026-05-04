// aarch64 ELF execution smoke per docs/31§4. Mirror of
// `kernel::elf_smoke` for arm: parse a hand-synthesised ELF64
// (`e_machine = EM_AARCH64`), register PT_LOAD as a
// `VmaBacking::KernelBytes` VMA in the global user `AddressSpace`
// (P2-17), register an anonymous stack VMA, drop to EL0 via
// `eret`. Demand-paging copies the ELF bytes into freshly-
// allocated user pages on first instruction-fetch.
//
// User blob: `write(1, "el\\n", 3); exit(0); brk #0`. The
// deliberate `brk` landmark after sysret-equivalent eret traps
// back to EL1 via VBAR_EL1+0x400 with ESR.EC=0x3C; the smoke
// handler logs success.

#![cfg(target_os = "oxide-kernel")]
#![cfg(target_arch = "aarch64")]

use crate::elf_load::load_static_blob;

/// Build a tiny aarch64 ELF64 image at compile time.
///   [0..64)    ehdr
///   [64..120)  PT_LOAD phdr
///   [120..128) pad
///   [128..168) code (40 B — write+exit+brk)
///   [168..171) "el\n"
const fn build_elf() -> [u8; 171] {
    let mut b = [0u8; 171];
    // e_ident
    b[0]=0x7f; b[1]=b'E'; b[2]=b'L'; b[3]=b'F';
    b[4]=2;   // ELFCLASS64
    b[5]=1;   // ELFDATA2LSB
    b[6]=1;   // EV_CURRENT
    // e_type=ET_EXEC, e_machine=EM_AARCH64 (183 = 0xB7), e_version=1
    b[16]=2; b[18]=0xB7; b[19]=0x00; b[20]=1;
    // e_entry = 0x400080
    let entry: u64 = 0x400080;
    let eb = entry.to_le_bytes();
    let mut i = 0; while i < 8 { b[24 + i] = eb[i]; i += 1; }
    // e_phoff = 64
    b[32]=64;
    // e_ehsize=64, e_phentsize=56, e_phnum=1
    b[52]=64; b[54]=56; b[56]=1;

    // PT_LOAD phdr at offset 64
    let p = 64;
    b[p+0]=1;     // p_type = PT_LOAD
    b[p+4]=5;     // p_flags = R|X (W^X invariant 3)
    // p_offset = 0
    // p_vaddr = 0x400000
    let v: u64 = 0x400000;
    let vb = v.to_le_bytes();
    i = 0; while i < 8 { b[p+16+i] = vb[i]; i += 1; }
    // p_paddr = same
    i = 0; while i < 8 { b[p+24+i] = vb[i]; i += 1; }
    // p_filesz = 171
    let fs: u64 = 171;
    let fb = fs.to_le_bytes();
    i = 0; while i < 8 { b[p+32+i] = fb[i]; i += 1; }
    // p_memsz = 171
    i = 0; while i < 8 { b[p+40+i] = fb[i]; i += 1; }
    // p_align = 0x1000
    let al: u64 = 0x1000;
    let ab = al.to_le_bytes();
    i = 0; while i < 8 { b[p+48+i] = ab[i]; i += 1; }

    // Code at file offset 128 (= vaddr 0x400080):
    //   movz w8, #1                       ; sys_write nr (oxide uses
    //                                       x86-style numbers across
    //                                       arches per the existing
    //                                       userspace_smoke_arm convention)
    //   movz x0, #1                        ; fd=1
    //   movz x1, #0x00A8                   ; buf low 16 bits
    //   movk x1, #0x0040, lsl #16          ; buf high → 0x4000A8
    //   movz x2, #3                        ; len
    //   svc  #0
    //   movz w8, #60                       ; sys_exit nr
    //   movz x0, #0                        ; code=0
    //   svc  #0
    //   brk  #0                            ; landmark
    let c = 128;
    // 0x52800028 = movz w8, #1
    b[c+0]=0x28; b[c+1]=0x00; b[c+2]=0x80; b[c+3]=0x52;
    // 0xD2800020 = movz x0, #1
    b[c+4]=0x20; b[c+5]=0x00; b[c+6]=0x80; b[c+7]=0xD2;
    // 0xD2801501 = movz x1, #0x00A8
    b[c+8]=0x01; b[c+9]=0x15; b[c+10]=0x80; b[c+11]=0xD2;
    // 0xF2A00801 = movk x1, #0x0040, lsl #16
    b[c+12]=0x01; b[c+13]=0x08; b[c+14]=0xA0; b[c+15]=0xF2;
    // 0xD2800062 = movz x2, #3
    b[c+16]=0x62; b[c+17]=0x00; b[c+18]=0x80; b[c+19]=0xD2;
    // 0xD4000001 = svc #0
    b[c+20]=0x01; b[c+21]=0x00; b[c+22]=0x00; b[c+23]=0xD4;
    // 0x52800788 = movz w8, #60
    b[c+24]=0x88; b[c+25]=0x07; b[c+26]=0x80; b[c+27]=0x52;
    // 0xD2800000 = movz x0, #0
    b[c+28]=0x00; b[c+29]=0x00; b[c+30]=0x80; b[c+31]=0xD2;
    // 0xD4000001 = svc #0
    b[c+32]=0x01; b[c+33]=0x00; b[c+34]=0x00; b[c+35]=0xD4;
    // 0xD4200000 = brk #0
    b[c+36]=0x00; b[c+37]=0x00; b[c+38]=0x20; b[c+39]=0xD4;
    // Buffer "el\n" at file offset 168 = vaddr 0x4000A8
    b[168]=b'e'; b[169]=b'l'; b[170]=b'\n';
    b
}

const ELF_BLOB_BYTES: [u8; 171] = build_elf();
const ELF_BLOB: &'static [u8] = &ELF_BLOB_BYTES;

/// User stack VMA disjoint from the ELF image. 4 KiB v1 stand-in.
const USER_STACK_VA:  u64 = 0x501_000;
const USER_STACK_TOP: u64 = USER_STACK_VA + 0x1000;

/// File-side address of the brk landmark — entry (0x400080) +
/// 36 (offset of the `brk #0` instruction within the code block).
const USER_RIP_BRK: u64 = 0x400080 + 36;

/// EL0 BRK landmark handler. Chains to user_as for legitimate
/// EL0 abort fault (instruction fetch / data access faults that
/// hit a registered VMA); on the deliberate `brk` from sys_exit's
/// eret landing, logs the success line.
fn elf_smoke_fault_handler(esr: u64, far: u64, elr: u64) -> bool {
    if crate::user_as::user_fault_handler(esr, far, elr) {
        return true;
    }
    let ec = (esr >> 26) & 0x3F;
    if ec == 0x3C && elr == USER_RIP_BRK {
        debug_irq! {
            klog::write_raw(b"[INFO]  elf-smoke-arm: ok EL0 BRK elr=");
            klog::write_hex_u64(elr);
            klog::write_raw(b" esr=");
            klog::write_hex_u64(esr);
            klog::write_raw(b"\n");
        }
    }
    false
}

/// Parse + load + drop to EL0. Diverges. Replaces
/// `userspace_smoke_arm::run` for the aarch64 boot path.
///
/// # SAFETY: caller is the boot path; user_as::init has run; PMM
/// + MmuOps + VBAR_EL1 + SVC dispatch all initialised; single-
/// CPU; DAIF.I masked.
/// # C: O(phdrs) parse + O(1) drop
/// # Ctx: pre-init, IRQ-off, single-CPU; diverges
pub unsafe fn run() -> ! {
    use vmm::{VmaBacking, VmaFlags, VmaProt};
    use hal::UserVirtAddr;

    let img = match crate::user_as::with(|as_| load_static_blob(ELF_BLOB, as_)) {
        Some(Ok(i))  => i,
        Some(Err(e)) => {
            debug_irq! {
                klog::write_raw(b"[FAULT] elf-smoke-arm: load failed err=");
                klog::write_dec_u64(e as u64);
                klog::write_raw(b"\n");
            }
            let _ = e;
            halt_forever();
        }
        None => {
            debug_irq! { klog::kerror!("elf-smoke-arm: user_as not initialised"); }
            halt_forever();
        }
    };

    debug_irq! {
        klog::write_raw(b"[INFO]  elf-smoke-arm: load ok entry=");
        klog::write_hex_u64(img.entry.as_u64());
        klog::write_raw(b" brk=");
        klog::write_hex_u64(img.brk.as_u64());
        klog::write_raw(b"\n");
    }

    // Anonymous stack VMA — demand-paged on first push (the blob
    // doesn't push, so this is precautionary).
    let stack_hint = match UserVirtAddr::new(USER_STACK_VA) {
        Some(u) => u,
        None    => { debug_irq! { klog::kerror!("elf-smoke-arm: bad stack VA"); } halt_forever(); }
    };
    let stack_r = crate::user_as::with(|as_| {
        as_.mmap(
            Some(stack_hint), 0x1000,
            VmaProt::READ | VmaProt::WRITE,
            VmaFlags::PRIVATE | VmaFlags::ANONYMOUS,
            VmaBacking::Anonymous,
            true,                          // MAP_FIXED
        )
    });
    if !matches!(stack_r, Some(Ok(_))) {
        debug_irq! { klog::kerror!("elf-smoke-arm: stack mmap failed"); }
        halt_forever();
    }

    // Spawn the loaded ELF as a user `Task` (mirrors x86 P2-13c).
    // schedule() switches into it via the IRQ-tail eret epilogue
    // using the synthetic frame from `new_user_with_irq_frame`.
    if !crate::sched::runqueue_active() {
        // SAFETY: boot path; allocator up; no concurrent runqueue users.
        unsafe { crate::sched::install_default_runqueue(); }
    }

    // SAFETY: handler 'static; pre-init swap.
    unsafe { hal_aarch64::install_fault_handler(elf_smoke_fault_handler); }

    let mm = match crate::user_as::clone_global_arc() {
        Some(a) => a,
        None    => { debug_irq! { klog::kerror!("elf-smoke-arm: AS clone failed"); } halt_forever(); }
    };
    // SAFETY: runqueue installed; PMM up; mm matches active TTBR0; per-arch HAL initialised; preempt-off.
    let task = match unsafe {
        crate::sched::spawn_user_thread(
            0xC0DE_0001, "elf-user-arm",
            img.entry.as_u64(),
            USER_STACK_TOP,
            mm,
        )
    } {
        Ok(t)  => t,
        Err(_) => { debug_irq! { klog::kerror!("elf-smoke-arm: spawn failed"); } halt_forever(); }
    };
    debug_irq! {
        klog::write_raw(b"[INFO]  elf-smoke-arm: spawned tid=0xC0DE0001 entry=");
        klog::write_hex_u64(img.entry.as_u64());
        klog::write_raw(b" sp=");
        klog::write_hex_u64(USER_STACK_TOP);
        klog::write_raw(b"\n");
    }

    // arm doesn't yet install /dev/console fd_table — sys_write
    // falls through to the in-table arch-neutral handler which
    // writes fd 1/2 to UART via klog. fd_table-mediated I/O on
    // arm rides P2-30c (when arm tty.rs gets a PL011 driver).
    let _task = task;

    // Open DAIF.I so the timer + future RX IRQs can fire.
    // SAFETY: opening DAIF.I lets GIC deliver IRQs.
    unsafe { core::arch::asm!("msr daifclr, #2", options(nomem, nostack, preserves_flags)); }
    // SAFETY: process ctx, runqueue installed, preempt-off; idle is the boot anchor.
    unsafe { crate::sched::schedule(); }
    // SAFETY: msr daifset re-masks DAIF.I after schedule returns to boot — matches the post-smoke discipline used elsewhere in the boot path.
    unsafe { core::arch::asm!("msr daifset, #2", options(nomem, nostack, preserves_flags)); }

    debug_irq! {
        klog::kinfo!("elf-smoke-arm: user task exited cleanly, boot resumed");
    }
    halt_forever();
}

fn halt_forever() -> ! {
    loop {
        // SAFETY: msr daifset masks IRQs; wfi parks the core; no wake — terminal halt.
        unsafe { core::arch::asm!("msr daifset, #2; wfi", options(nomem, nostack, preserves_flags)); }
    }
}
