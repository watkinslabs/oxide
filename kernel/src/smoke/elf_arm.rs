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

#![cfg(target_arch = "aarch64")]

use elf_load::load_static_blob;

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

/// 4 KiB stack for the in-tree el-blob smoke (entry 0x400080 hand-
/// coded ELF). Sufficient for the no-fn-call hello+exit binary.
const USER_STACK_VA:  u64 = 0x501_000;
const USER_STACK_TOP: u64 = USER_STACK_VA + 0x1000;

/// 64 KiB stack for the busybox /sbin/init spawn — identical layout
/// to the x86 init path (`crate::smoke::elf::EXEC_USER_STACK_VA/_LEN`).
/// busybox + child fork+exec chains overrun a 4 KiB stack on the
/// first wide musl frame; with the prior 0x501000/4 KiB layout the
/// fork child SIGSEGV'd at far=0x500f70 (one page below the stack
/// base) when init walked deeper than the page boundary.
const INIT_STACK_LEN: u64 = 0x10000;
const INIT_STACK_VA:  u64 = hal::USER_VA_END - 0x20000;
const INIT_STACK_TOP: u64 = INIT_STACK_VA + INIT_STACK_LEN;

/// File-side address of the brk landmark — entry (0x400080) +
/// 36 (offset of the `brk #0` instruction within the code block).
const USER_RIP_BRK: u64 = 0x400080 + 36;

/// EL0 BRK landmark handler. Chains to user_as for legitimate
/// EL0 abort fault (instruction fetch / data access faults that
/// hit a registered VMA); on the deliberate `brk` from sys_exit's
/// eret landing, logs the success line.
fn elf_smoke_fault_handler(esr: u64, far: u64, elr: u64) -> bool {
    if pmm::user_as::user_fault_handler(esr, far, elr) {
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
/// `crate::smoke::userspace_arm::run` for the aarch64 boot path.
///
/// # SAFETY: caller is the boot path; pmm::user_as::init has run; PMM
/// + MmuOps + VBAR_EL1 + SVC dispatch all initialised; single-
/// CPU; DAIF.I masked.
/// # C: O(phdrs) parse + O(1) drop
/// # Ctx: pre-init, IRQ-off, single-CPU; diverges
pub unsafe fn run() -> ! {
    use vmm::{VmaBacking, VmaFlags, VmaProt};
    use hal::UserVirtAddr;

    let img = match pmm::user_as::with(|as_| load_static_blob(ELF_BLOB, as_)) {
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
    let stack_r = pmm::user_as::with(|as_| {
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
    if !sched::live::runqueue_active() {
        // SAFETY: boot path; allocator up; no concurrent runqueue users.
        unsafe { sched::live::install_default_runqueue(); }
    }

    // SAFETY: handler 'static; pre-init swap.
    unsafe { hal_aarch64::install_fault_handler(elf_smoke_fault_handler); }

    let mm = match pmm::user_as::clone_global_arc() {
        Some(a) => a,
        None    => { debug_irq! { klog::kerror!("elf-smoke-arm: AS clone failed"); } halt_forever(); }
    };
    // SAFETY: runqueue installed; PMM up; mm matches active TTBR0; per-arch HAL initialised; preempt-off.
    let task = match unsafe {
        sched::live::spawn_user_thread(
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
    unsafe { sched::live::schedule(); }
    // SAFETY: msr daifset re-masks DAIF.I after schedule returns to boot — matches the post-smoke discipline used elsewhere in the boot path.
    unsafe { core::arch::asm!("msr daifset, #2", options(nomem, nostack, preserves_flags)); }

    debug_irq! {
        klog::kinfo!("elf-smoke-arm: user task exited cleanly, boot resumed");
    }

    // ARM lockstep with x86: after the smoke ELF exits, spawn
    // /sbin/init from the mounted ext4 rootfs and run the
    // init→svcd→agetty→login chain. Mirrors `crate::smoke::elf::run_as_task`
    // post-smoke behavior. Without this the arm boot path halted
    // forever right here, leaving the user staring at a kernel-only
    // log with no way to interact (`make qemu-arm` was useless).
    spawn_init_from_rootfs_arm();

    // Schedule loop with IRQs unmasked so the timer-tick UART poll
    // keeps draining bytes into the tty rx ringbuffer.
    loop {
        // SAFETY: dispatch ctx; runqueue installed; preempt-off.
        unsafe { sched::live::schedule(); }
        // SAFETY: msr daifclr opens DAIF.I to allow the timer / UART
        // IRQ to wake us; wfi parks until next IRQ; both privileged at EL1.
        unsafe { core::arch::asm!("msr daifclr, #2; wfi; msr daifset, #2",
            options(nomem, nostack, preserves_flags)); }
    }
}

/// aarch64 mirror of `crate::smoke::elf::spawn_user_blob_smoke` for the
/// init blob. Looks up /sbin/init (then /init) in the mounted ext4
/// rootfs, allocates a fresh per-task L0 page table, builds an
/// AddressSpace, activates it (TTBR0 swap), loads the static-PIE
/// init binary, mmaps a user stack, spawns a user task on the
/// runqueue. Returns when the spawn machinery is done; the task
/// runs on the next schedule().
fn spawn_init_from_rootfs_arm() {
    use vmm::{AddressSpace, VmaBacking, VmaFlags, VmaProt};
    use hal::{MmuOps, UserVirtAddr};

    // PID 1: load /sbin/init from the mounted rootfs (busybox
    // hardlinked to /sbin/init via /bin/busybox).
    let init_blob: &'static [u8] = {
        let bytes_opt = ext4::rootfs::read_file(b"/sbin/init")
            .or_else(|| ext4::rootfs::read_file(b"/init"));
        match bytes_opt {
            Some(b) => alloc::boxed::Box::leak(b.into_boxed_slice()),
            None => {
                debug_irq! { klog::kinfo!("elf-smoke-arm: no /sbin/init in rootfs; halting"); }
                return;
            }
        }
    };

    // SAFETY: PMM + MmuOps up; new_user_l0 returns a fresh frame zeroed and populated with the kernel half.
    let root_pa = match unsafe { hal_aarch64::mmu_ops::new_user_l0() } {
        Some(p) => p,
        None    => { debug_irq! { klog::kerror!("init-arm: new_user_l0 failed"); } return; }
    };
    let mm = match AddressSpace::new(root_pa) {
        Ok(a)  => a,
        Err(_) => { debug_irq! { klog::kerror!("init-arm: AS::new failed"); } return; }
    };

    // SAFETY: per-AS L0 was constructed with kernel-half shared from master so kernel mappings remain valid; TTBR0 swap legal at EL1 IRQ-off.
    unsafe { <hal_aarch64::mmu_ops::ArmMmu as MmuOps>::activate(root_pa); }

    let img = match elf_load::load_static_blob(init_blob, &mm) {
        Ok(i)  => i,
        Err(_) => { debug_irq! { klog::kerror!("init-arm: load_static_blob failed"); } return; }
    };

    let stack_hint = match UserVirtAddr::new(INIT_STACK_VA) {
        Some(u) => u,
        None    => { debug_irq! { klog::kerror!("init-arm: bad stack VA"); } return; }
    };
    if mm.mmap(
        Some(stack_hint), INIT_STACK_LEN as usize,
        VmaProt::READ | VmaProt::WRITE,
        VmaFlags::PRIVATE | VmaFlags::ANONYMOUS,
        VmaBacking::Anonymous,
        true,
    ).is_err() {
        debug_irq! { klog::kerror!("init-arm: stack mmap failed"); }
        return;
    }

    // Pre-fault every stack page so kernel-side `build_user_stack`
    // writes don't take EL1 same-EL data aborts. The boot fault
    // handler routes through `pmm::user_as::with(|as_| …)` which serves
    // the GLOBAL boot AS, not the per-task `mm` we just activated;
    // a faulting kernel write here therefore can't be demand-paged.
    // Mirrors the x86 path (which sidesteps the issue by mapping the
    // stack into the global AS); arm uses a fresh per-task L0 so we
    // walk + install leaves explicitly.
    {
        use hal::{Pa, PageFlags, PageSize, Va};
        let prot = (VmaProt::READ | VmaProt::WRITE).to_page_flags();
        let mut va = INIT_STACK_VA;
        while va < INIT_STACK_TOP {
            let pa = match pmm::setup::alloc_one_frame() {
                Some(p) => p,
                None    => {
                    debug_irq! { klog::kerror!("init-arm: stack page alloc failed"); }
                    return;
                }
            };
            // Zero through HHDM mirror.
            // SAFETY: pa is a freshly-allocated PMM frame; HHDM mirror is mapped writable in the kernel L0 captured at boot; 4 KiB owned exclusively until the M::map below.
            unsafe {
                let dst = (pmm::user_as::hhdm_offset() + pa) as *mut u8;
                core::ptr::write_bytes(dst, 0, hal::PAGE_SIZE_BYTES as usize);
                <hal_aarch64::mmu_ops::ArmMmu as MmuOps>::map(
                    Va(va), Pa(pa), prot, PageSize::P4K,
                );
            }
            va += hal::PAGE_SIZE_BYTES;
        }
    }

    // F153-1: build a real SysV initial stack with argv[0]=/sbin/init
    // so busybox dispatches the `init` applet. Same shape as the
    // x86 spawn_user_blob_smoke path.
    let random16 = {
        use hal::TimerOps;
        let ns = hal_aarch64::ArmTimerOps::monotonic_ns().0;
        let mut r = [0u8; 16];
        for i in 0..16 { r[i] = (ns >> ((i % 8) * 8)) as u8 ^ (i as u8 * 0x9b); }
        r
    };
    let argv0: &[&[u8]] = &[b"/sbin/init"];
    // SAFETY: per-AS just activated; build_user_stack writes via active TTBR0; demand-fault resolves the new stack page.
    let new_sp = unsafe {
        elf_load::stack::build_user_stack(
            INIT_STACK_TOP,
            argv0, &[],
            &img,
            &random16,
            b"/sbin/init",
        )
    }.unwrap_or(INIT_STACK_TOP);

    // F152-2: leave TPIDR_EL0 = 0 on first user entry. musl crt1's
    // __init_tls mmaps a TCB and writes TPIDR_EL0 directly (EL0
    // can write TPIDR_EL0 on aarch64) before any TLS access.
    // SAFETY: msr tpidr_el0, xzr at EL1 is always legal; user
    // crt1 overwrites with the real TCB before first TLS load.
    unsafe {
        core::arch::asm!(
            "msr tpidr_el0, xzr",
            options(nomem, nostack, preserves_flags),
        );
    }

    // SAFETY: runqueue installed; PMM up; mm matches active TTBR0; per-arch HAL initialised; preempt-off; vpid stamped pre-enqueue so busybox-init's first syscall sees PID 1.
    let task = match unsafe {
        sched::live::spawn_user_thread_with_vpid(
            0xC0DE_0002, /* vtgid */ 1, /* vtid */ 1, "init",
            img.entry.as_u64(),
            new_sp,
            mm,
        )
    } {
        Ok(t) => t,
        Err(_) => {
            debug_irq! { klog::kerror!("init-arm: spawn_user_thread failed"); }
            return;
        }
    };

    // Wire fd 0/1/2 to the console so busybox-as-shell (and any
    // child after fork+exec) has working stdin/stdout/stderr —
    // mirrors crate::smoke::elf::spawn_user_blob_smoke on x86. Without this
    // a forked child running real-libc /bin/sh hits EBADF on its
    // first write to stderr and exits without printing anything.
    let fdt = crate::dev::console::init_console_fd_table();
    // SAFETY: task isn't yet scheduled; we are sole writer to its fd_table slot per the single-mutator-per-active-CPU invariant in `13§5`.
    unsafe { task.replace_fd_table(Some(fdt)); }
    let _task = task;

    debug_irq! { klog::kinfo!("init-arm: spawned"); }
}

/// arm-side init lookup helper. Tries /sbin/init first, then /init,
/// falling back to the embedded INIT_REAL_BLOB which is x86-only —
/// so on aarch64 if the rootfs has no init we return None and
/// caller halts.
fn halt_forever() -> ! {
    loop {
        // SAFETY: msr daifset masks IRQs; wfi parks the core; no wake — terminal halt.
        unsafe { core::arch::asm!("msr daifset, #2; wfi", options(nomem, nostack, preserves_flags)); }
    }
}
