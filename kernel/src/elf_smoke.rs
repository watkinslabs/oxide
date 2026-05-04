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

/// Build an init-like fork+wait4+execve+exit ELF64 at compile
/// time. Demonstrates the canonical shell pattern: parent forks
/// a child, child execve's a different program, parent waits for
/// it to exit, parent exits cleanly. Layout:
///
///   [0..64)     ehdr
///   [64..120)   PT_LOAD phdr
///   [120..128)  pad
///   [128..199)  code (71 B)
///   [199..200)  'y' (selector → YO_BLOB)
///
/// Pseudo-code:
///   if (pid = fork()) == 0:
///     execve("y")                  ; child runs YO_BLOB
///     exit(1)                       ; failsafe
///   wait4(-1, NULL, 0, NULL)       ; parent reaps child
///   exit(0)
const fn build_elf() -> [u8; 200] {
    let mut b = [0u8; 200];
    b[0]=0x7f; b[1]=b'E'; b[2]=b'L'; b[3]=b'F';
    b[4]=2; b[5]=1; b[6]=1;
    b[16]=2; b[18]=62; b[20]=1;
    let entry: u64 = 0x400080;
    let eb = entry.to_le_bytes();
    let mut i = 0; while i < 8 { b[24 + i] = eb[i]; i += 1; }
    b[32]=64;
    b[52]=64; b[54]=56; b[56]=1;

    let p = 64;
    b[p+0]=1; b[p+4]=5;                  // PT_LOAD R|X
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

    let c = 128;
    // [0x00] B8 39 00 00 00       mov $57, %eax     ; sys_fork
    b[c+0]=0xB8; b[c+1]=0x39;
    // [0x05] 0F 05                 syscall
    b[c+5]=0x0F; b[c+6]=0x05;
    // [0x07] 85 C0                 test %eax, %eax
    b[c+7]=0x85; b[c+8]=0xC0;
    // [0x09] 75 1E                 jne +0x1E → 0x29 (parent → wait1)
    b[c+9]=0x75; b[c+10]=0x1E;
    // CHILD PATH:
    // [0x0B] BF C7 00 40 00       mov $0x4000C7, %edi   ; "y" selector
    b[c+11]=0xBF; b[c+12]=0xC7; b[c+13]=0x00; b[c+14]=0x40; b[c+15]=0x00;
    // [0x10] B8 3B 00 00 00       mov $59, %eax         ; sys_execve
    b[c+16]=0xB8; b[c+17]=0x3B;
    // [0x15] 31 F6                 xor %esi, %esi
    b[c+21]=0x31; b[c+22]=0xF6;
    // [0x17] 31 D2                 xor %edx, %edx
    b[c+23]=0x31; b[c+24]=0xD2;
    // [0x19] 0F 05                 syscall (execve)
    b[c+25]=0x0F; b[c+26]=0x05;
    // [0x1B] B8 3C 00 00 00       mov $60, %eax (failsafe)
    b[c+27]=0xB8; b[c+28]=0x3C;
    // [0x20] BF 01 00 00 00       mov $1, %edi
    b[c+32]=0xBF; b[c+33]=0x01;
    // [0x25] 0F 05                 syscall (exit)
    b[c+37]=0x0F; b[c+38]=0x05;
    // [0x27] 0F 0B                 ud2
    b[c+39]=0x0F; b[c+40]=0x0B;
    // PARENT PATH (wait1):
    // [0x29] B8 3D 00 00 00       mov $61, %eax         ; sys_wait4
    b[c+41]=0xB8; b[c+42]=0x3D;
    // [0x2E] BF FF FF FF FF       mov $-1, %edi         ; pid = -1 (any child)
    b[c+46]=0xBF; b[c+47]=0xFF; b[c+48]=0xFF; b[c+49]=0xFF; b[c+50]=0xFF;
    // [0x33] 31 F6                 xor %esi, %esi       ; wstatus = NULL
    b[c+51]=0x31; b[c+52]=0xF6;
    // [0x35] 31 D2                 xor %edx, %edx       ; options = 0
    b[c+53]=0x31; b[c+54]=0xD2;
    // [0x37] 45 31 D2              xor %r10d, %r10d     ; rusage = NULL
    b[c+55]=0x45; b[c+56]=0x31; b[c+57]=0xD2;
    // [0x3A] 0F 05                 syscall (wait4)
    b[c+58]=0x0F; b[c+59]=0x05;
    // PARENT EXIT:
    // [0x3C] B8 3C 00 00 00       mov $60, %eax
    b[c+60]=0xB8; b[c+61]=0x3C;
    // [0x41] 31 FF                 xor %edi, %edi
    b[c+65]=0x31; b[c+66]=0xFF;
    // [0x43] 0F 05                 syscall (exit)
    b[c+67]=0x0F; b[c+68]=0x05;
    // [0x45] 0F 0B                 ud2
    b[c+69]=0x0F; b[c+70]=0x0B;
    // Path selector 'y' at file offset 199 = vaddr 0x4000C7.
    b[199]=b'y';
    b
}

const ELF_BLOB_BYTES: [u8; 200] = build_elf();
const ELF_BLOB: &'static [u8] = &ELF_BLOB_BYTES;

/// Build a "writes 2-char message + exit" ELF64. `c0`/`c1` are
/// the two output chars; the program writes `[c0, c1, '\n']` then
/// exits cleanly.
const fn build_named_blob(c0: u8, c1: u8) -> [u8; 164] {
    let mut b = [0u8; 164];
    b[0]=0x7f; b[1]=b'E'; b[2]=b'L'; b[3]=b'F';
    b[4]=2; b[5]=1; b[6]=1;
    b[16]=2; b[18]=62; b[20]=1;
    let entry: u64 = 0x400080;
    let eb = entry.to_le_bytes();
    let mut i = 0; while i < 8 { b[24 + i] = eb[i]; i += 1; }
    b[32]=64;
    b[52]=64; b[54]=56; b[56]=1;

    let p = 64;
    b[p+0]=1; b[p+4]=5;                          // PT_LOAD R|X
    let v: u64 = 0x400000;
    let vb = v.to_le_bytes();
    i = 0; while i < 8 { b[p+16+i] = vb[i]; i += 1; }
    i = 0; while i < 8 { b[p+24+i] = vb[i]; i += 1; }
    let fs: u64 = 164;
    let fb = fs.to_le_bytes();
    i = 0; while i < 8 { b[p+32+i] = fb[i]; i += 1; }
    i = 0; while i < 8 { b[p+40+i] = fb[i]; i += 1; }
    let al: u64 = 0x1000;
    let ab = al.to_le_bytes();
    i = 0; while i < 8 { b[p+48+i] = ab[i]; i += 1; }

    // Code at file offset 128 (vaddr 0x400080) — write 3 bytes
    // (c0, c1, '\n') + exit. Buffer at file offset 161 = vaddr
    // 0x4000A1.
    let c = 128;
    b[c+0]=0xB8; b[c+1]=0x01;                                  // mov $1, %eax
    b[c+5]=0xBF; b[c+6]=0x01;                                  // mov $1, %edi
    b[c+10]=0xBE; b[c+11]=0xA1; b[c+12]=0x00; b[c+13]=0x40; b[c+14]=0x00; // mov $0x4000A1, %esi
    b[c+15]=0xBA; b[c+16]=0x03;                                // mov $3, %edx
    b[c+20]=0x0F; b[c+21]=0x05;                                // syscall
    b[c+22]=0xB8; b[c+23]=0x3C;                                // mov $60, %eax
    b[c+27]=0x31; b[c+28]=0xFF;                                // xor %edi, %edi
    b[c+29]=0x0F; b[c+30]=0x05;                                // syscall
    b[c+31]=0x0F; b[c+32]=0x0B;                                // ud2
    b[161]=c0; b[162]=c1; b[163]=b'\n';
    b
}

const HI_BLOB_BYTES: [u8; 164] = build_named_blob(b'h', b'i');
const YO_BLOB_BYTES: [u8; 164] = build_named_blob(b'y', b'o');
/// Programs the table-driven `sys_execve` can load by name (P2-21b).
pub const HI_BLOB: &'static [u8] = &HI_BLOB_BYTES;
pub const YO_BLOB: &'static [u8] = &YO_BLOB_BYTES;

/// Look up the kernel-static ELF for a given path's first byte
/// (v1 selector — full path lookup waits on VFS per docs/16).
/// Returns the matching blob or `None` for unknown paths.
/// # C: O(1)
pub fn lookup_blob(selector: u8) -> Option<&'static [u8]> {
    match selector {
        b'h' => Some(HI_BLOB),
        b'y' => Some(YO_BLOB),
        _    => None,
    }
}

/// Default blob for the `path = NULL` legacy path (P2-21 v0).
/// Retained so older test paths keep working.
pub const EXEC_BLOB: &'static [u8] = HI_BLOB;

/// Stack VA for an execve'd program. v1: same per-process VA as
/// the original ELF's stack (different AS, so no clash).
pub const EXEC_USER_STACK_VA:  u64 = 0x501_000;
pub const EXEC_USER_STACK_TOP: u64 = EXEC_USER_STACK_VA + 0x1000;

/// User stack VMA placed disjoint from the ELF image. 4 KiB; v1
/// stand-in for the docs/31§4 8 MiB MAP_GROWSDOWN stack, which
/// rides P2-18 alongside SIGSEGV delivery.
const USER_STACK_VA:  u64 = 0x501_000;
const USER_STACK_TOP: u64 = USER_STACK_VA + 0x1000;

/// ud2 landmark addresses. The init-like ELF has ud2 at
/// `0x400080 + 0x27` (child failsafe) and `0x400080 + 0x45`
/// (parent post-exit, never reached on clean exits since
/// `sys_exit` unwinds via Zombie + reschedule). Named blobs'
/// ud2 is at `0x400080 + 0x1F`.
const USER_RIP_UD2_CHILD_FS: u64 = 0x400080 + 0x27;
const USER_RIP_UD2_PARENT:   u64 = 0x400080 + 0x45;
const USER_RIP_UD2_EXEC:     u64 = 0x400080 + 0x1F;

/// `#UD` landmark handler. Chains to user_as for legitimate
/// demand-page faults; on the deliberate ud2 from sys_exit's
/// sysretq landing, logs the success line.
fn elf_smoke_fault_handler(vec: u64, err: u64, rip: u64, cr2: u64) -> bool {
    if crate::user_as::user_fault_handler(vec, err, rip, cr2) {
        return true;
    }
    if vec == 6 && (rip == USER_RIP_UD2_CHILD_FS
                    || rip == USER_RIP_UD2_PARENT
                    || rip == USER_RIP_UD2_EXEC) {
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
