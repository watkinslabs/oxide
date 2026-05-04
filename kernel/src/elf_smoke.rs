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

/// Build an init-like fork+wait4+execve loop ELF64 at compile
/// time. Two iterations: parent forks → child execs YO ("yo\\n");
/// parent waits → forks → child execs HI ("hi\\n"); parent waits
/// → exits. ECHO_BLOB is registered in `lookup_blob` for future
/// programs to execve("e"); a 3-iteration init-blob demo of
/// read+write end-to-end rides P3-02b once the fd_table read
/// path through ConsoleInode is fully traced.
///
/// Layout:
///   [0..64)     ehdr
///   [64..120)   PT_LOAD phdr
///   [120..128)  pad
///   [128..248)  code (120 B): 2 iterations × 60 B
///   [248..259)  final exit (11 B)
///   [259..260)  'y' (vaddr 0x400103)
///   [260..261)  'h' (vaddr 0x400104)
const fn build_elf() -> [u8; 261] {
    let mut b = [0u8; 261];
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
    let fs: u64 = 261;
    let fb = fs.to_le_bytes();
    i = 0; while i < 8 { b[p+32+i] = fb[i]; i += 1; }
    i = 0; while i < 8 { b[p+40+i] = fb[i]; i += 1; }
    let al: u64 = 0x1000;
    let ab = al.to_le_bytes();
    i = 0; while i < 8 { b[p+48+i] = ab[i]; i += 1; }

    // 2 iterations × 60 B each. Selectors:
    //   iter 1: 'y' at vaddr 0x400103 (sel_lo = 0x03)
    //   iter 2: 'h' at vaddr 0x400104 (sel_lo = 0x04)
    let c = 128;
    iter_block(&mut b, c,      0x03);
    iter_block(&mut b, c + 60, 0x04);
    // Final exit at offset 120.
    let e = c + 120;
    b[e+0]=0xB8; b[e+1]=0x3C;             // mov $60, %eax
    b[e+5]=0x31; b[e+6]=0xFF;             // xor %edi, %edi
    b[e+7]=0x0F; b[e+8]=0x05;             // syscall (exit)
    b[e+9]=0x0F; b[e+10]=0x0B;            // ud2
    // Selectors at file offsets 259, 260 → vaddrs 0x400103, 0x400104.
    b[259]=b'y';
    b[260]=b'h';
    b
}

/// Emit one fork+jne+child(execve `sel_lo`)+failsafe+wait4 block
/// at file-offset `off` within `b`. `sel_lo` is the low byte of
/// the selector VA (0x400000 | (sel_lo as u32)) — the selector
/// itself sits at file offset == vaddr & 0xfff. Block size = 60 B.
const fn iter_block(b: &mut [u8; 261], off: usize, sel_lo: u8) {
    // [0x00] mov $57, %eax            ; sys_fork
    b[off+0]=0xB8; b[off+1]=0x39;
    // [0x05] syscall
    b[off+5]=0x0F; b[off+6]=0x05;
    // [0x07] test %eax, %eax
    b[off+7]=0x85; b[off+8]=0xC0;
    // [0x09] jne +0x1E → 0x29 (wait4)  ; parent path
    b[off+9]=0x75; b[off+10]=0x1E;
    // CHILD PATH (file offset off+0x0B..off+0x29):
    // [0x0B] mov $sel_va, %edi
    b[off+11]=0xBF; b[off+12]=sel_lo; b[off+13]=0x01; b[off+14]=0x40; b[off+15]=0x00;
    // [0x10] mov $59, %eax            ; sys_execve
    b[off+16]=0xB8; b[off+17]=0x3B;
    // [0x15] xor %esi, %esi           ; argv=NULL
    b[off+21]=0x31; b[off+22]=0xF6;
    // [0x17] xor %edx, %edx           ; envp=NULL
    b[off+23]=0x31; b[off+24]=0xD2;
    // [0x19] syscall (execve)
    b[off+25]=0x0F; b[off+26]=0x05;
    // [0x1B] mov $60, %eax            ; failsafe exit
    b[off+27]=0xB8; b[off+28]=0x3C;
    // [0x20] mov $1, %edi
    b[off+32]=0xBF; b[off+33]=0x01;
    // [0x25] syscall (exit)
    b[off+37]=0x0F; b[off+38]=0x05;
    // [0x27] ud2
    b[off+39]=0x0F; b[off+40]=0x0B;
    // PARENT WAIT4 (file offset off+0x29..off+0x3C):
    // [0x29] mov $61, %eax            ; sys_wait4
    b[off+41]=0xB8; b[off+42]=0x3D;
    // [0x2E] mov $-1, %edi
    b[off+46]=0xBF; b[off+47]=0xFF; b[off+48]=0xFF; b[off+49]=0xFF; b[off+50]=0xFF;
    // [0x33] xor %esi, %esi
    b[off+51]=0x31; b[off+52]=0xF6;
    // [0x35] xor %edx, %edx
    b[off+53]=0x31; b[off+54]=0xD2;
    // [0x37] xor %r10d, %r10d
    b[off+55]=0x45; b[off+56]=0x31; b[off+57]=0xD2;
    // [0x3A] syscall (wait4)
    b[off+58]=0x0F; b[off+59]=0x05;
}

const ELF_BLOB_BYTES: [u8; 261] = build_elf();
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

/// Build an ECHO ELF: read 1 byte from fd=0, write to fd=1, exit.
/// v1 demonstrates the fd_table → ConsoleInode → tty ringbuffer
/// end-to-end (P3-02). The 1-byte read buffer lives at the heap's
/// initial brk (vaddr 0x401000) — the loader pre-registers an
/// Anonymous R|W VMA covering the heap so the page demand-faults
/// to a fresh zero frame on first write. Keeps PT_LOAD R|X (no
/// W^X violation per docs/31§2 invariant 3).
const fn build_echo_blob() -> [u8; 173] {
    let mut b = [0u8; 173];
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
    let fs: u64 = 173;
    let fb = fs.to_le_bytes();
    i = 0; while i < 8 { b[p+32+i] = fb[i]; i += 1; }
    i = 0; while i < 8 { b[p+40+i] = fb[i]; i += 1; }
    let al: u64 = 0x1000;
    let ab = al.to_le_bytes();
    i = 0; while i < 8 { b[p+48+i] = ab[i]; i += 1; }

    // Code at file offset 128 (vaddr 0x400080):
    //   mov $0, %eax            ; sys_read (= 0)
    //   mov $0, %edi            ; fd=0
    //   mov $0x401000, %esi     ; buf in heap region (R|W via P2-32)
    //   mov $1, %edx            ; len=1
    //   syscall
    //   mov $1, %eax            ; sys_write (= 1)
    //   mov $1, %edi            ; fd=1
    //   ; esi/edx still hold buf/len from the read
    //   syscall
    //   mov $60, %eax           ; sys_exit
    //   xor %edi, %edi
    //   syscall
    //   ud2
    let c = 128;
    b[c+0]=0xB8;                                   // mov $0, %eax (zero default)
    b[c+5]=0xBF;                                   // mov $0, %edi
    b[c+10]=0xBE; b[c+11]=0x00; b[c+12]=0x10; b[c+13]=0x40; b[c+14]=0x00;  // 0x401000
    b[c+15]=0xBA; b[c+16]=0x01;                    // mov $1, %edx
    b[c+20]=0x0F; b[c+21]=0x05;                    // syscall (read)
    b[c+22]=0xB8; b[c+23]=0x01;                    // mov $1, %eax
    b[c+27]=0xBF; b[c+28]=0x01;                    // mov $1, %edi
    b[c+32]=0x0F; b[c+33]=0x05;                    // syscall (write)
    b[c+34]=0xB8; b[c+35]=0x3C;                    // mov $60, %eax
    b[c+39]=0x31; b[c+40]=0xFF;                    // xor %edi, %edi
    b[c+41]=0x0F; b[c+42]=0x05;                    // syscall (exit)
    b[c+43]=0x0F; b[c+44]=0x0B;                    // ud2
    b
}

const ECHO_BLOB_BYTES: [u8; 173] = build_echo_blob();
/// "echo" program: read 1 byte from fd=0, write it to fd=1,
/// exit. Selector: 'e'.
pub const ECHO_BLOB: &'static [u8] = &ECHO_BLOB_BYTES;

/// Look up the kernel-static ELF for a given path's first byte
/// (v1 selector — full path lookup waits on VFS per docs/16).
/// Returns the matching blob or `None` for unknown paths.
/// # C: O(1)
pub fn lookup_blob(selector: u8) -> Option<&'static [u8]> {
    match selector {
        b'h' => Some(HI_BLOB),
        b'y' => Some(YO_BLOB),
        b'e' => Some(ECHO_BLOB),
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

/// ud2 landmark addresses for the init-like ELF. Each iteration
/// has a child failsafe ud2 at `entry+iter_off+0x27`; the final
/// exit's ud2 is at `entry+0x84`. Named blobs' ud2 lives at
/// `entry+0x1F`.
const USER_RIP_UD2_ITER1_FS: u64 = 0x400080 + 0x27;
const USER_RIP_UD2_ITER2_FS: u64 = 0x400080 + 60 + 0x27;
const USER_RIP_UD2_FINAL:    u64 = 0x400080 + 2*60 + 9;
const USER_RIP_UD2_EXEC:     u64 = 0x400080 + 0x1F;
const USER_RIP_UD2_ECHO:     u64 = 0x400080 + 0x2B;

/// `#UD` landmark handler. Chains to user_as for legitimate
/// demand-page faults; on the deliberate ud2 from sys_exit's
/// sysretq landing, logs the success line.
fn elf_smoke_fault_handler(vec: u64, err: u64, rip: u64, cr2: u64) -> bool {
    if crate::user_as::user_fault_handler(vec, err, rip, cr2) {
        return true;
    }
    if vec == 6 && (rip == USER_RIP_UD2_ITER1_FS
                    || rip == USER_RIP_UD2_ITER2_FS
                    || rip == USER_RIP_UD2_FINAL
                    || rip == USER_RIP_UD2_EXEC
                    || rip == USER_RIP_UD2_ECHO) {
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
    let task = match unsafe {
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

    // Install init's fd table — fd 0/1/2 → /dev/console (P2-30a).
    let fdt = crate::dev_console::init_console_fd_table();
    // SAFETY: task isn't yet scheduled (we just spawned it); we are sole writer.
    unsafe { task.replace_fd_table(Some(fdt)); }
    let _task = task;

    debug_irq! {
        klog::write_raw(b"[INFO]  elf-smoke: spawned tid=0xC0DE0001 entry=");
        klog::write_hex_u64(img.entry.as_u64());
        klog::write_raw(b" sp=");
        klog::write_hex_u64(USER_STACK_TOP);
        klog::write_raw(b"\n");
    }

    // Pre-fill the TTY ringbuffer with a test byte so the third
    // iteration's ECHO program (P3-02) can read+write a byte
    // non-interactively. Real interactive use rides on UART RX
    // bytes pushed via `tty::tick_poll_uart` from the timer ISR.
    crate::tty::inject_for_smoke(b"A");

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
