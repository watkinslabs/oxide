// First userspace `iretq` smoke per `20§3` step 12 / Phase 1→2 boundary.
//
// Drops to CPL=3 by building a synthetic IRET frame and executing
// `iretq`. User code is `syscall; ud2` (0F 05 / 0F 0B). The CPU
// transitions back to CPL=0 via IA32_LSTAR (P2-01); the dispatcher
// logs receipt and halts. Proves end-to-end:
//   - kernel-owned GDT user CS/SS descriptors are walkable (P1-93),
//   - TSS.RSP0 is the kernel-side stack on CPL3→CPL0 (P1-94),
//   - U/S=1 propagated through every interior PT entry (P1-95),
//   - syscall MSRs (LSTAR/STAR/FMASK + EFER.SCE) are wired (P2-01).
//
// Layout:
//   USER_CODE_VA  0x0040_0000   1 page R|W|X|U  → first byte = 0xCC
//   USER_STACK_VA 0x0050_0000   1 page R|W|U
//   IRQ_STACK     PMM frame      → TSS.RSP0 = top
//
// On success the installed fault handler logs
//   `[INFO] userspace-eret-smoke: ok ring3 #BP rip=…`
// then halts. The pre-existing `boot: kernel ready, halting` is no
// longer reached on x86 builds with this smoke wired; the success
// log replaces it as the boot-completion signal.

#![cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]

use hal::{MmuOps, Pa, PageFlags, PageSize, Va};
use hal_x86_64::{install_fault_handler, set_rsp0, USER_CS, USER_DS};

const USER_CODE_VA:  u64 = 0x0040_0000;
const USER_STACK_VA: u64 = 0x0050_0000;
const USER_STACK_TOP: u64 = USER_STACK_VA + 0x1000;
const KSTACK_SIZE: u64 = 0x1000;

// User blob: mmap+write+write+exit+ud2 — exercises real demand-paging
// (P2-12) end-to-end on top of the bound syscall slots.
//
// Sequence:
//   1. mmap(NULL, 4096, R|W, PRIVATE|ANON, -1, 0)  -> rax = base VA
//   2. movl $0xDEADBEEF, (%rax)                    -> #PF, demand-page resolves
//   3. write(1, "hi\n", 3)                          -> rax = 3
//   4. exit(0)                                      -> rax = 0
//   5. ud2                                          -> tripwire (smoke landmark)
//
// Encoding (74 bytes):
//   B8 09 00 00 00          mov  $9, %eax           ; sys_mmap nr
//   31 FF                    xor  %edi, %edi          ; addr=NULL
//   BE 00 10 00 00          mov  $0x1000, %esi       ; len=4096
//   BA 03 00 00 00          mov  $3, %edx            ; prot=R|W
//   41 BA 22 00 00 00       mov  $0x22, %r10d        ; flags=PRIV|ANON
//   49 C7 C0 FF FF FF FF    mov  $-1, %r8            ; fd=-1
//   45 31 C9                 xor  %r9d, %r9d          ; off=0
//   0F 05                    syscall
//   C7 00 EF BE AD DE        movl $0xDEADBEEF, (%rax) ; demand-page on first write
//   B8 01 00 00 00          mov  $1, %eax            ; sys_write nr
//   BF 01 00 00 00          mov  $1, %edi            ; fd=stdout
//   BE 00 01 40 00          mov  $0x400100, %esi     ; buf
//   BA 03 00 00 00          mov  $3, %edx            ; len
//   0F 05                    syscall
//   B8 3C 00 00 00          mov  $60, %eax           ; sys_exit nr
//   31 FF                    xor  %edi, %edi          ; code=0
//   0F 05                    syscall
//   0F 0B                    ud2                       ; tripwire
const USER_BLOB: [u8; 74] = [
    0xB8, 0x09, 0x00, 0x00, 0x00,                       // mov  $9, %eax
    0x31, 0xFF,                                         // xor  %edi, %edi
    0xBE, 0x00, 0x10, 0x00, 0x00,                       // mov  $0x1000, %esi
    0xBA, 0x03, 0x00, 0x00, 0x00,                       // mov  $3, %edx
    0x41, 0xBA, 0x22, 0x00, 0x00, 0x00,                 // mov  $0x22, %r10d
    0x49, 0xC7, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF,           // mov  $-1, %r8
    0x45, 0x31, 0xC9,                                   // xor  %r9d, %r9d
    0x0F, 0x05,                                         // syscall (mmap)
    0xC7, 0x00, 0xEF, 0xBE, 0xAD, 0xDE,                 // movl $0xDEADBEEF, (%rax)
    0xB8, 0x01, 0x00, 0x00, 0x00,                       // mov  $1, %eax
    0xBF, 0x01, 0x00, 0x00, 0x00,                       // mov  $1, %edi
    0xBE, 0x00, 0x01, 0x40, 0x00,                       // mov  $0x400100, %esi
    0xBA, 0x03, 0x00, 0x00, 0x00,                       // mov  $3, %edx
    0x0F, 0x05,                                         // syscall (write)
    0xB8, 0x3C, 0x00, 0x00, 0x00,                       // mov  $60, %eax
    0x31, 0xFF,                                         // xor  %edi, %edi
    0x0F, 0x05,                                         // syscall (exit)
    0x0F, 0x0B,                                         // ud2
];
const USER_BUF_OFF: u64 = 0x100;
const USER_BUF_BYTES: &[u8] = b"hi\n";

/// User code addr of the final `ud2` (sysretq from sys_exit lands here).
const USER_RIP_POST_SYSRET: u64 = USER_CODE_VA + (USER_BLOB.len() as u64) - 2;

/// Handler that watches for `#UD` from user at the ud2 tripwire —
/// confirms full ring0→ring3→ring0 round-trip via syscall+sysretq.
fn user_sysret_handler(vec: u64, err: u64, rip: u64, cr2: u64) -> bool {
    // Delegate demand-paging first per `11§5`: any user #PF whose VA
    // lies inside a registered VMA gets resolved by `user_as`. If
    // the demand-paging path returns true (handled), the dispatcher
    // retries the faulting instruction and we never see the smoke
    // landmark. Only faults user_as didn't recognize fall through
    // to the smoke's #UD landmark check below.
    if crate::user_as::user_fault_handler(vec, err, rip, cr2) {
        return true;
    }
    if vec == 6 && rip == USER_RIP_POST_SYSRET {
        debug_irq! {
            klog::write_raw(b"[INFO]  userspace-sysret-smoke: ok ring3 #UD rip=");
            klog::write_hex_u64(rip);
            klog::write_raw(b"\n");
        }
    }
    false
}

/// Map a single 4 KiB user page at `va` with the given flags.
/// # SAFETY: caller asserts `va` is unmapped on entry; PMM + MmuOps
/// state initialised; single-CPU pre-init.
unsafe fn map_user_page<M: MmuOps>(va: u64, flags: PageFlags) -> Option<u64> {
    let pa = pmm_setup::alloc_one_frame()?;
    // SAFETY: per fn contract; flags carry USER for the leaf U bit.
    unsafe { M::map(Va(va), Pa(pa), flags, PageSize::P4K); }
    Some(pa)
}

/// Run the smoke against `M = X86Mmu`. `hhdm_offset` is the kernel's
/// HHDM base — used to derive a kernel VA for the IRQ landing stack.
/// # SAFETY: caller is the boot path; PMM + MmuOps + GDT + TSS + IDT
/// initialised; single-CPU; IRQs masked. Diverges (halts) on success
/// or first failure.
/// # C: O(1) modulo PT walks
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn run<M: MmuOps>(hhdm_offset: u64) -> ! {
    // Map user code page R|W|X|U (W is for our 0xCC write; W^X is
    // accepted only because this is a one-shot smoke).
    // SAFETY: USER_CODE_VA is unmapped on entry to the smoke; PMM + MmuOps state initialised by kernel_main pre-init; single-CPU.
    let code_pa = match unsafe {
        map_user_page::<M>(
            USER_CODE_VA,
            PageFlags::READ | PageFlags::WRITE | PageFlags::EXEC | PageFlags::USER,
        )
    } {
        Some(pa) => pa,
        None => {
            debug_irq! { klog::kerror!("userspace-eret-smoke: code-page alloc failed"); }
            halt_forever();
        }
    };
    // Map user stack page R|W|U.
    // SAFETY: USER_STACK_VA is unmapped on entry; PMM + MmuOps state initialised by kernel_main pre-init; single-CPU.
    let _stack_pa = match unsafe {
        map_user_page::<M>(
            USER_STACK_VA,
            PageFlags::READ | PageFlags::WRITE | PageFlags::USER,
        )
    } {
        Some(pa) => pa,
        None => {
            debug_irq! { klog::kerror!("userspace-eret-smoke: stack-page alloc failed"); }
            halt_forever();
        }
    };
    let _ = code_pa;

    // Write the user code blob and the "hi\n" buffer it points at.
    // SAFETY: USER_CODE_VA mapped W|U|EXEC; sole owner this CPU.
    unsafe {
        for (i, b) in USER_BLOB.iter().enumerate() {
            core::ptr::write_volatile((USER_CODE_VA + i as u64) as *mut u8, *b);
        }
        for (i, b) in USER_BUF_BYTES.iter().enumerate() {
            core::ptr::write_volatile((USER_CODE_VA + USER_BUF_OFF + i as u64) as *mut u8, *b);
        }
    }

    // Per-CPU IRQ landing stack + fault handler install + drop to
    // ring 3 — common to every "drop to user mode" path. Factored
    // into `drop_to_ring3` for reuse by the ELF smoke (P2-16b).
    // SAFETY: GDT/TSS/IDT/syscall MSRs initialised; user code+stack mapped USER+EXEC/USER+WRITE; single-CPU; IRQs masked.
    unsafe { drop_to_ring3(USER_CODE_VA, USER_STACK_TOP, hhdm_offset, user_sysret_handler); }
}

/// Set TSS RSP0 to a fresh kernel stack and `iretq` into user mode
/// at `(rip, rsp)`. Diverges. Allocates one PMM frame for the
/// ring-3→ring-0 landing stack and stores its top in TSS.RSP0 so
/// the next user→kernel transition lands cleanly. Installs
/// `fault_handler` so the deliberate ud2 / brk landmark at the
/// end of the user blob can be observed.
///
/// # SAFETY: caller has fully initialised GDT, TSS, IDT, syscall
/// MSRs (P1-93..P1-96); user code at `rip` is mapped USER+EXEC;
/// user stack at `rsp` is mapped USER+WRITE (or will demand-page
/// from a registered VMA); CPL=0; IRQs masked.
/// # C: O(1) modulo PMM alloc
/// # Ctx: pre-init, IRQ-off, single-CPU; diverges
pub unsafe fn drop_to_ring3(
    rip: u64,
    rsp: u64,
    hhdm_offset: u64,
    fault_handler: hal_x86_64::FaultHandler,
) -> ! {
    let kstack_pa = match pmm_setup::alloc_one_frame() {
        Some(p) => p,
        None => {
            debug_irq! { klog::kerror!("drop_to_ring3: kstack alloc failed"); }
            halt_forever();
        }
    };
    let kstack_top = hhdm_offset + kstack_pa + KSTACK_SIZE;
    // SAFETY: TSS in kernel BSS; serialised pre-init; rsp0 points at top of freshly-allocated, HHDM-mapped 4 KiB frame.
    unsafe { set_rsp0(kstack_top); }
    // SAFETY: handler fn is 'static; pre-init single-CPU swap.
    let _prev = unsafe { install_fault_handler(fault_handler) };

    debug_irq! {
        klog::write_raw(b"[INFO]  drop-to-ring3: cs=");
        klog::write_hex_u64(USER_CS as u64);
        klog::write_raw(b" rip=");
        klog::write_hex_u64(rip);
        klog::write_raw(b" ss=");
        klog::write_hex_u64(USER_DS as u64);
        klog::write_raw(b" rsp=");
        klog::write_hex_u64(rsp);
        klog::write_raw(b"\n");
    }

    // CPU pops iretq frame in order: RIP, CS, RFLAGS, RSP, SS.
    // RFLAGS = 0x002 (IF=0, reserved bit 1) — keep IRQs masked while
    // in user; landmarks fire deterministically.
    // SAFETY: synthetic CPL3-bound iretq frame; values built from
    // kernel-validated constants.
    unsafe {
        core::arch::asm!(
            "push {ss}",
            "push {rsp_u}",
            "push {rfl}",
            "push {cs}",
            "push {rip_u}",
            "iretq",
            ss    = in(reg) USER_DS as u64,
            rsp_u = in(reg) rsp,
            rfl   = in(reg) 0x002u64,
            cs    = in(reg) USER_CS as u64,
            rip_u = in(reg) rip,
            options(noreturn),
        );
    }
}

fn halt_forever() -> ! {
    loop {
        // SAFETY: hlt at CPL=0 parks until next IRQ; with IRQs masked
        // and no NMI source on the QEMU smoke, this is the terminal
        // state.
        unsafe { core::arch::asm!("hlt", options(nomem, nostack, preserves_flags)); }
    }
}
