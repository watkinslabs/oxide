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

/// Build a fork+branch+exit ELF64 image at compile time. Layout:
///   [0..64)     ehdr
///   [64..120)   PT_LOAD phdr
///   [120..128)  pad
///   [128..196)  code (68 B): fork + jz child + parent write "P\n"
///                            + jmp exit + child write "C\n" + exit + ud2
///   [196..198)  "P\n"
///   [198..200)  "C\n"
///
/// Sequence (entry = 0x400080):
///   mov  $57, %eax                ; sys_fork
///   syscall
///   test %eax, %eax                ; rax=0 in child, rax=child_tid in parent
///   jz   child
/// parent:
///   mov  $1, %eax                  ; sys_write
///   mov  $1, %edi                  ; fd=1
///   mov  $0x4000C4, %esi           ; "P\n"
///   mov  $2, %edx
///   syscall
///   jmp  exit
/// child:
///   mov  $1, %eax
///   mov  $1, %edi
///   mov  $0x4000C6, %esi           ; "C\n"
///   mov  $2, %edx
///   syscall
/// exit:
///   mov  $60, %eax
///   xor  %edi, %edi
///   syscall
///   ud2                             ; landmark
const fn build_elf() -> [u8; 200] {
    let mut b = [0u8; 200];
    // e_ident
    b[0]=0x7f; b[1]=b'E'; b[2]=b'L'; b[3]=b'F';
    b[4]=2; b[5]=1; b[6]=1;             // class64, LE, EV_CURRENT
    b[16]=2; b[18]=62; b[20]=1;          // ET_EXEC, EM_X86_64, version=1
    let entry: u64 = 0x400080;
    let eb = entry.to_le_bytes();
    let mut i = 0; while i < 8 { b[24 + i] = eb[i]; i += 1; }
    b[32]=64;                            // e_phoff
    b[52]=64; b[54]=56; b[56]=1;         // e_ehsize, e_phentsize, e_phnum

    // PT_LOAD phdr at offset 64
    let p = 64;
    b[p+0]=1;                            // p_type = PT_LOAD
    b[p+4]=5;                            // p_flags = R|X
    let v: u64 = 0x400000;
    let vb = v.to_le_bytes();
    i = 0; while i < 8 { b[p+16+i] = vb[i]; i += 1; }
    i = 0; while i < 8 { b[p+24+i] = vb[i]; i += 1; }
    let fs: u64 = 200;
    let fb = fs.to_le_bytes();
    i = 0; while i < 8 { b[p+32+i] = fb[i]; i += 1; }
    i = 0; while i < 8 { b[p+40+i] = fb[i]; i += 1; }
    let al: u64 = 0x1000;
    let ab = al.to_le_bytes();
    i = 0; while i < 8 { b[p+48+i] = ab[i]; i += 1; }

    // Code at file offset 128 (vaddr 0x400080).
    let c = 128;
    // [0x00] B8 39 00 00 00       mov $57, %eax     ; sys_fork
    b[c+0]=0xB8; b[c+1]=0x39;
    // [0x05] 0F 05                 syscall
    b[c+5]=0x0F; b[c+6]=0x05;
    // [0x07] 85 C0                 test %eax, %eax
    b[c+7]=0x85; b[c+8]=0xC0;
    // [0x09] 74 18                 jz +0x18 → 0x23 (child)
    b[c+9]=0x74; b[c+10]=0x18;
    // [0x0B] parent: mov $1, %eax
    b[c+11]=0xB8; b[c+12]=0x01;
    // [0x10] mov $1, %edi
    b[c+16]=0xBF; b[c+17]=0x01;
    // [0x15] mov $0x4000C4, %esi
    b[c+21]=0xBE; b[c+22]=0xC4; b[c+23]=0x00; b[c+24]=0x40; b[c+25]=0x00;
    // [0x1A] mov $2, %edx
    b[c+26]=0xBA; b[c+27]=0x02;
    // [0x1F] syscall
    b[c+31]=0x0F; b[c+32]=0x05;
    // [0x21] jmp +0x16 → 0x39 (exit)
    b[c+33]=0xEB; b[c+34]=0x16;
    // [0x23] child: mov $1, %eax
    b[c+35]=0xB8; b[c+36]=0x01;
    // [0x28] mov $1, %edi
    b[c+40]=0xBF; b[c+41]=0x01;
    // [0x2D] mov $0x4000C6, %esi
    b[c+45]=0xBE; b[c+46]=0xC6; b[c+47]=0x00; b[c+48]=0x40; b[c+49]=0x00;
    // [0x32] mov $2, %edx
    b[c+50]=0xBA; b[c+51]=0x02;
    // [0x37] syscall
    b[c+55]=0x0F; b[c+56]=0x05;
    // [0x39] exit: mov $60, %eax
    b[c+57]=0xB8; b[c+58]=0x3C;
    // [0x3E] xor %edi, %edi
    b[c+62]=0x31; b[c+63]=0xFF;
    // [0x40] syscall
    b[c+64]=0x0F; b[c+65]=0x05;
    // [0x42] ud2
    b[c+66]=0x0F; b[c+67]=0x0B;
    // Buffers "P\n" at 0x4000C4 (file offset 196), "C\n" at 0x4000C6.
    b[196]=b'P'; b[197]=b'\n';
    b[198]=b'C'; b[199]=b'\n';
    b
}

const ELF_BLOB_BYTES: [u8; 200] = build_elf();
const ELF_BLOB: &'static [u8] = &ELF_BLOB_BYTES;

/// User stack VMA placed disjoint from the ELF image. 4 KiB; v1
/// stand-in for the docs/31§4 8 MiB MAP_GROWSDOWN stack, which
/// rides P2-18 alongside SIGSEGV delivery.
const USER_STACK_VA:  u64 = 0x501_000;
const USER_STACK_TOP: u64 = USER_STACK_VA + 0x1000;

/// File-side address of the ud2 landmark — entry (0x400080) +
/// 0x42 (offset of `0F 0B` at the end of the fork+branch+exit
/// code block per `build_elf`).
const USER_RIP_UD2: u64 = 0x400080 + 0x42;

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

/// Spawn the loaded ELF as a real user `Task` on the runqueue
/// and `schedule()` into it. The task carries
/// `Arc<AddressSpace>`, so future fork/execve can reach it via
/// `sched::current().mm`. Diverges via the deliberate ud2
/// landmark after sys_exit's sysretq → smoke fault handler.
///
/// Foundation for fork/execve: introduces a real "current user
/// task" backed by `mm`, replacing the prior `drop_to_ring3`
/// flow that ran user code without any Task wrapper.
///
/// Installs a fresh runqueue if one isn't already present.
///
/// # SAFETY: caller is the boot path; user_as::init has run; PMM
/// + GDT + TSS + IDT + syscall MSRs initialised; single-CPU;
/// IRQs masked.
/// # C: O(phdrs) parse + O(log N) enqueue
/// # Ctx: pre-init, IRQ-off, single-CPU; diverges
pub unsafe fn run_as_task(_hhdm_offset: u64) -> ! {
    if !crate::sched::runqueue_active() {
        // SAFETY: boot path; allocator up; no concurrent runqueue users.
        unsafe { crate::sched::install_default_runqueue(); }
    }
    use vmm::{VmaBacking, VmaFlags, VmaProt};
    use hal::UserVirtAddr;

    let img = match crate::user_as::with(|as_| {
        let img = load_static_blob(ELF_BLOB, as_)?;
        // Stack VMA — anonymous, demand-paged on first push.
        let stack_hint = UserVirtAddr::new(USER_STACK_VA)
            .ok_or(crate::elf_load::LoadError::Einval)?;
        as_.mmap(
            Some(stack_hint), 0x1000,
            VmaProt::READ | VmaProt::WRITE,
            VmaFlags::PRIVATE | VmaFlags::ANONYMOUS,
            VmaBacking::Anonymous,
            true,
        ).map_err(|_| crate::elf_load::LoadError::Enomem)?;
        Ok::<_, crate::elf_load::LoadError>(img)
    }) {
        Some(Ok(i))  => i,
        Some(Err(e)) => {
            debug_irq! {
                klog::write_raw(b"[FAULT] elf-smoke: setup failed err=");
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

    // Install the smoke fault handler.
    // SAFETY: handler fn is 'static; pre-init single-CPU swap.
    unsafe { hal_x86_64::install_fault_handler(elf_smoke_fault_handler); }

    let mm = match crate::user_as::clone_global_arc() {
        Some(a) => a,
        None    => { debug_irq! { klog::kerror!("elf-smoke: AS clone failed"); } halt_forever(); }
    };

    // Spawn the user task on the runqueue.
    // SAFETY: runqueue installed by kernel_main earlier; mm matches active CR3.
    let _task = match unsafe {
        crate::sched::spawn_user_thread(
            0xC0DE_0001, "elf-user",
            img.entry.as_u64(),
            USER_STACK_TOP,
            mm,
        )
    } {
        Ok(t)  => t,
        Err(_) => { debug_irq! { klog::kerror!("elf-smoke: spawn failed"); } halt_forever(); }
    };

    debug_irq! {
        klog::write_raw(b"[INFO]  elf-smoke: spawned tid=0xC0DE0001 entry=");
        klog::write_hex_u64(img.entry.as_u64());
        klog::write_raw(b" sp=");
        klog::write_hex_u64(USER_STACK_TOP);
        klog::write_raw(b"\n");
    }

    // STI so timer IRQs can drive preempt-on-IRQ-exit if the
    // task ever yields back to kernel; our smoke task runs IF=0
    // through to its first sys_exit so this is a no-op for now.
    // SAFETY: STI legal at CPL=0; pairs with the boot-path discipline that masked IRQs at entry; the runqueue + IRQ epilogue tolerate timer-driven preemption.
    unsafe { core::arch::asm!("sti", options(nomem, nostack)); }
    // schedule() picks the user task (lowest vruntime in CFS),
    // updates current, and Context::switch's into the synthetic
    // iretq frame → drop to ring 3 at e_entry. User runs to ud2
    // landmark; #UD halts in the smoke fault handler.
    // SAFETY: process ctx; runqueue installed; preempt-off.
    unsafe { crate::sched::schedule(); }

    // Boot resumes here when the user task exits via `sys_exit`
    // (P2-13d): kernel_sys_exit marks the task Zombie + reschedules,
    // picker returns to idle (boot anchor), Context::switch lands
    // back here on boot's saved regs.
    debug_irq! {
        klog::kinfo!("elf-smoke: user task exited cleanly, boot resumed");
    }
    halt_forever();
}

/// Parse + load + drop to ring 3 directly (no Task wrapper).
/// Diverges. Retained for the boot path that hasn't yet
/// installed a runqueue (or for debugging).
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
