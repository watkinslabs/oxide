// ELF execution smoke per docs/31§4. Parses a hand-synthesised
// ELF64, loads it into the global user `AddressSpace` via
// `VmaBacking::KernelBytes` (P2-17), registers an anonymous stack
// VMA, and drops to ring 3 at `e_entry`. Demand-paging copies
// the ELF bytes into freshly-allocated user pages on first
// access — no manual `MmuOps::map` calls.
//
// The user blob does `write(1, "el\\n", 3); exit(0); ud2`; the
// `#UD` landmark at the end is caught by the smoke handler so we
// have a deterministic halt point matching the prior
// `userspace_smoke` shape.

#![cfg(target_os = "oxide-kernel")]
#![cfg(target_arch = "x86_64")]

use crate::elf_load::load_static_blob;

/// Build a tiny ELF64 image at compile time.
///   [0..64)    ehdr
///   [64..120)  PT_LOAD phdr
///   [120..128) pad
///   [128..161) code (33 B — write+exit+ud2)
///   [161..164) "el\n"
const fn build_elf() -> [u8; 164] {
    let mut b = [0u8; 164];
    // e_ident
    b[0]=0x7f; b[1]=b'E'; b[2]=b'L'; b[3]=b'F';
    b[4]=2;   // ELFCLASS64
    b[5]=1;   // ELFDATA2LSB
    b[6]=1;   // EV_CURRENT
    // e_type=ET_EXEC, e_machine=EM_X86_64, e_version=1
    b[16]=2; b[18]=62; b[20]=1;
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
    b[p+4]=5;     // p_flags = R|X
    // p_offset = 0
    // p_vaddr = 0x400000
    let v: u64 = 0x400000;
    let vb = v.to_le_bytes();
    i = 0; while i < 8 { b[p+16+i] = vb[i]; i += 1; }
    // p_paddr = same
    i = 0; while i < 8 { b[p+24+i] = vb[i]; i += 1; }
    // p_filesz = 164
    let fs: u64 = 164;
    let fb = fs.to_le_bytes();
    i = 0; while i < 8 { b[p+32+i] = fb[i]; i += 1; }
    // p_memsz = 164
    i = 0; while i < 8 { b[p+40+i] = fb[i]; i += 1; }
    // p_align = 0x1000
    let al: u64 = 0x1000;
    let ab = al.to_le_bytes();
    i = 0; while i < 8 { b[p+48+i] = ab[i]; i += 1; }

    // Code at file offset 128 (= vaddr 0x400080):
    //   mov $1, %eax              ; sys_write
    //   mov $1, %edi              ; fd=1
    //   mov $0x4000A1, %esi       ; buf
    //   mov $3, %edx              ; len
    //   syscall
    //   mov $60, %eax             ; sys_exit
    //   xor %edi, %edi
    //   syscall
    //   ud2                        ; landmark
    let c = 128;
    b[c+0]=0xB8; b[c+1]=0x01;
    b[c+5]=0xBF; b[c+6]=0x01;
    b[c+10]=0xBE; b[c+11]=0xA1; b[c+12]=0x00; b[c+13]=0x40; b[c+14]=0x00;
    b[c+15]=0xBA; b[c+16]=0x03;
    b[c+20]=0x0F; b[c+21]=0x05;
    b[c+22]=0xB8; b[c+23]=0x3C;
    b[c+27]=0x31; b[c+28]=0xFF;
    b[c+29]=0x0F; b[c+30]=0x05;
    b[c+31]=0x0F; b[c+32]=0x0B;
    // Buffer "el\n" at file offset 161 = vaddr 0x4000A1
    b[161]=b'e'; b[162]=b'l'; b[163]=b'\n';
    b
}

const ELF_BLOB_BYTES: [u8; 164] = build_elf();
const ELF_BLOB: &'static [u8] = &ELF_BLOB_BYTES;

/// User stack VMA placed disjoint from the ELF image. 4 KiB; v1
/// stand-in for the docs/31§4 8 MiB MAP_GROWSDOWN stack, which
/// rides P2-18 alongside SIGSEGV delivery.
const USER_STACK_VA:  u64 = 0x501_000;
const USER_STACK_TOP: u64 = USER_STACK_VA + 0x1000;

/// File-side address of the ud2 landmark — entry (0x400080) +
/// 31 (offset of `0F 0B` inside the synthesised code block).
const USER_RIP_UD2: u64 = 0x400080 + 31;

/// `#UD` landmark handler. Chains to user_as for legitimate
/// demand-page faults; on the deliberate ud2 from sys_exit's
/// sysretq landing, logs the success line.
fn elf_smoke_fault_handler(vec: u64, err: u64, rip: u64, cr2: u64) -> bool {
    if crate::user_as::user_fault_handler(vec, err, rip, cr2) {
        return true;
    }
    if vec == 6 && rip == USER_RIP_UD2 {
        debug_irq! {
            klog::write_raw(b"[INFO]  elf-smoke: ok ring3 #UD rip=");
            klog::write_hex_u64(rip);
            klog::write_raw(b"\n");
        }
    }
    false
}

/// Parse + load + drop to ring 3. Diverges. Replaces
/// `userspace_smoke::run` for the x86_64 boot path.
///
/// # SAFETY: caller is the boot path; user_as::init has run; PMM
/// + MmuOps + GDT + TSS + IDT + syscall MSRs all initialised;
/// single-CPU; IRQs masked.
/// # C: O(phdrs) parse + O(1) drop
/// # Ctx: pre-init, IRQ-off, single-CPU; diverges
pub unsafe fn run(hhdm_offset: u64) -> ! {
    use vmm::{VmaBacking, VmaFlags, VmaProt};
    use hal::UserVirtAddr;

    // 1. Load the ELF into the global AS.
    let img = match crate::user_as::with(|as_| load_static_blob(ELF_BLOB, as_)) {
        Some(Ok(i))  => i,
        Some(Err(e)) => {
            debug_irq! {
                klog::write_raw(b"[FAULT] elf-smoke: load failed err=");
                klog::write_dec_u64(e as u64);
                klog::write_raw(b"\n");
            }
            let _ = e;
            halt_forever();
        }
        None => {
            debug_irq! { klog::kerror!("elf-smoke: user_as not initialised"); }
            halt_forever();
        }
    };

    debug_irq! {
        klog::write_raw(b"[INFO]  elf-smoke: load ok entry=");
        klog::write_hex_u64(img.entry.as_u64());
        klog::write_raw(b" brk=");
        klog::write_hex_u64(img.brk.as_u64());
        klog::write_raw(b"\n");
    }

    // 2. Register an anonymous user-stack VMA. Demand-paging
    //    on first push gives us a fresh zeroed frame.
    let stack_hint = match UserVirtAddr::new(USER_STACK_VA) {
        Some(u) => u,
        None    => { debug_irq! { klog::kerror!("elf-smoke: bad stack VA"); } halt_forever(); }
    };
    let stack_r = crate::user_as::with(|as_| {
        as_.mmap(
            Some(stack_hint), 0x1000,
            VmaProt::READ | VmaProt::WRITE,
            VmaFlags::PRIVATE | VmaFlags::ANONYMOUS,
            VmaBacking::Anonymous,
            true,                          // MAP_FIXED at USER_STACK_VA
        )
    });
    if !matches!(stack_r, Some(Ok(_))) {
        debug_irq! { klog::kerror!("elf-smoke: stack mmap failed"); }
        halt_forever();
    }

    // 3. Drop to ring 3 at e_entry. iretq's instruction-fetch at
    //    `entry` will take a #PF that user_as_fault_handler
    //    resolves via the KernelBytes-backed VMA — that's the
    //    real demand-page path the spec wants.
    // SAFETY: GDT/TSS/IDT/syscall MSRs initialised by kernel_main; entry & stack VMAs registered above; CPL=0; IRQs masked.
    unsafe {
        crate::userspace_smoke::drop_to_ring3(
            img.entry.as_u64(),
            USER_STACK_TOP,
            hhdm_offset,
            elf_smoke_fault_handler,
        );
    }
}

fn halt_forever() -> ! {
    loop {
        // SAFETY: cli+hlt parks the CPU until next IRQ; with IRQs masked there's no wake — terminal halt.
        unsafe { core::arch::asm!("cli; hlt", options(nomem, nostack, preserves_flags)); }
    }
}
