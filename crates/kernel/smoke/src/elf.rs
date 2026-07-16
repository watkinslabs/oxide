// PID 1 boot + user-task spawn (x86_64). Loads the real init
// (`/lib/systemd/systemd`, else `/sbin/init`/`/init`) from the mounted ext4
// rootfs and spawns it as PID 1 via the proven user-thread primitive (returns
// to ring 3 through the task's saved frame on first schedule — Linux
// ret_from_fork). The initial stack is mapped into the new AS eagerly
// (setup_arg_pages), so the stack build does not depend on a global address
// space. No synthetic bringup ELFs. docs/31§4, docs/53.

#![cfg(target_arch = "x86_64")]

use elf_load::load_static_blob;

/// Load an executable by path from the mounted ext4 rootfs. Returns the file
/// bytes leaked to `'static` (kernel-lifetime), or `None` if absent. One leak
/// per exec is fine for v1 — Phase 7a page-cache replaces this.
/// # C: O(path lookup)
pub fn lookup_blob_by_path(path: &[u8]) -> Option<&'static [u8]> {
    #[cfg(target_os = "oxide-kernel")]
    {
        if let Some(bytes) = ext4::rootfs::read_file(path) {
            let leaked: &'static [u8] = alloc::boxed::Box::leak(bytes.into_boxed_slice());
            return Some(leaked);
        }
    }
    None
}

/// User stack length for boot-spawned user blobs. 64 KiB matches
/// the execve path; the prior 4 KiB underflowed in the first wide
/// musl init frame and the prior VA (0x501_000) collided with
/// a large init's .text segment, chopping a hole in code while
/// giving init no room. Place near the top of user-half VA so we
/// stay disjoint from any reasonable ELF text.
pub const EXEC_USER_STACK_LEN: u64 = 0x10000;
pub const EXEC_USER_STACK_VA:  u64 = hal::USER_VA_END - 0x20000;
pub const EXEC_USER_STACK_TOP: u64 = EXEC_USER_STACK_VA + EXEC_USER_STACK_LEN;

const USER_STACK_LEN: u64 = EXEC_USER_STACK_LEN;
const USER_STACK_VA:  u64 = EXEC_USER_STACK_VA;
const USER_STACK_TOP: u64 = EXEC_USER_STACK_TOP;

/// User-page fault handler: demand-paging for PIE relocs + stack/heap growth.
/// # C: O(1) typical
fn user_fault_handler(vec: u64, err: u64, rip: u64, cr2: u64) -> bool {
    if pmm::user_as::user_fault_handler(vec, err, rip, cr2) {
        return true; // resolved: demand-page / COW / stack-grow → retry the insn
    }
    // Unresolvable. err bit 2 (PF_USER) set ⇒ the access came from ring 3: a
    // genuine userspace bad pointer. Linux delivers SIGSEGV, whose default
    // action terminates the process — it does NOT halt the kernel. Kill the
    // faulting task and schedule away so init reaps it (status 11/SEGV) and the
    // boot continues; a single service's wild pointer must not take down the
    // machine. A kernel-mode (PF_USER clear) unresolved fault IS fatal — fall
    // through to `false` so the asm halt loop surfaces the real kernel bug.
    const PF_USER: u64 = 0x4;
    if err & PF_USER != 0 {
        sched::live::terminate_current_with_signal(sched::Signum::Sigsegv as u8);
        // terminate_current_with_signal diverges (schedules away).
    }
    false
}

/// Boot PID 1: install the runqueue + user-fault handler, arm the LAPIC timer,
/// load the real init from the rootfs, and spawn it as PID 1, then schedule
/// forever. No kernel-embedded init (51§2 invariant 1).
/// # SAFETY: boot path; pmm::user_as::init ran; PMM+GDT+TSS+IDT+syscall MSRs
/// up; single-CPU; IRQs masked.
/// # C: O(phdrs) parse + O(log N) enqueue
/// # Ctx: pre-init, IRQ-off, single-CPU; diverges
pub unsafe fn run_as_task(_hhdm_offset: u64) -> ! {
    if !sched::live::runqueue_active() {
        // SAFETY: boot path; allocator up; no concurrent runqueue users.
        unsafe { sched::live::install_default_runqueue(); }
    }
    // SAFETY: handler fn is 'static; pre-init single-CPU swap.
    unsafe { hal_x86_64::install_fault_handler(user_fault_handler); }
    // Arm the LAPIC periodic timer so preemption and deadline wakes run under
    // userspace. UART RX is owned by the 8250 IRQ4 handler.
    // SAFETY: LAPIC enabled by smoke_device_map_x86; same period as boot.
    unsafe { let _ = arch_irq::lapic::timer_periodic(1_000_000); }
    // NB: IRQs stay MASKED across the init spawn below. `spawn_user_blob_
    // with_vpid` enqueues PID 1 Runnable + sets need_resched BEFORE it
    // installs PID 1's console fd table (stdin/out/err). If a timer tick
    // fired in that window it could schedule PID 1 into ring 3 with NO fd
    // table → its first writev(1/2) returns EBADF → systemd/ld-musl exits
    // 127 → silent login hang. This was the flaky x86 SMP=2 login failure
    // (2-vCPU QEMU timing hit the window ~25%; B75 diag pinned it via the
    // recent-syscall ring: writev=-9 before exit_group(127)). `sti` moves
    // to AFTER the spawn so PID 1 is fully formed before its first schedule.

    // PID 1 = systemd (oxide distro init), loaded from the rootfs. Prefer
    // /init when present: imagectl's desktop roots install it as a regular
    // fallback copy with a patched PT_INTERP that avoids early symlink-heavy
    // loader paths. CLI roots without /init still use the distro locations.
    let init_candidates: &[&[u8]] = &[
        b"/init",
        b"/lib/systemd/systemd",
        b"/sbin/init",
    ];
    let mut init_path: &[u8] = b"/init";
    let mut init_blob_opt = None;
    // Honor the Linux `init=<path>` kernel parameter first (init=/bin/bash for a
    // rescue/diagnostic shell, init=/sbin/init, …). Falls through to the distro
    // candidates when absent or the named path is missing from the rootfs.
    if let Some(p) = cmdline::init_path() {
        if let Some(blob) = lookup_blob_by_path(p) {
            init_path = p;
            init_blob_opt = Some(blob);
        }
    }
    if init_blob_opt.is_none() {
        for path in init_candidates {
            if let Some(blob) = lookup_blob_by_path(path) {
                init_path = path;
                init_blob_opt = Some(blob);
                break;
            }
        }
    }
    hal::kassert!(init_blob_opt.is_some(),
        "no /lib/systemd/systemd, /sbin/init or /init in rootfs (51§2 invariant 1)");
    let init_blob = init_blob_opt.unwrap_or(b"");
    #[cfg(feature = "debug-boot")]
    {
        klog::write_raw(b"[INFO]  init: selected ");
        klog::write_raw(init_path);
        klog::write_raw(b"\n");
    }
    // systemd init requires getpid()==1: stamp vtgid=1/vtid=1 before the
    // task is registry/runqueue-visible.
    // SAFETY: boot-path discipline; user_as / runqueue installed.
    unsafe {
        spawn_user_blob_with_vpid(
            init_blob, "init",
            0xC0DE_0002, /* vtgid */ 1, /* vtid */ 1,
            &[init_path],
        );
    }
    // PID 1 is now fully formed (fd table installed). Enable IRQs: the
    // idle anchor's first schedule() drops into ring 3 with IF=1, and the
    // periodic timer drives preemption + UART poll from here on.
    // SAFETY: STI legal at CPL=0; runqueue + PID 1 fully set up above.
    unsafe { core::arch::asm!("sti", options(nomem, nostack)); }

    // Idle anchor. schedule() runs any runnable task (diverging into it); it
    // returns here only when nothing is runnable — then sti+hlt parks the CPU
    // with IRQs ENABLED so the periodic timer keeps firing. UART IRQs deliver
    // stdin bytes, while the timer tick runs tick_wake_expired for tasks parked
    // on poll/select deadlines (e.g. systemd's terminal-query ppoll).
    // A bare `loop { schedule() }` spins with IF=0 after the first switch-back,
    // so no timer IRQ fires and deadline waits hang forever.
    loop {
        // SAFETY: dispatch ctx; runqueue installed; preempt-off.
        unsafe { sched::live::schedule(); }
        // SAFETY: STI+HLT at CPL=0 idles with IRQs on until the next IRQ.
        unsafe { core::arch::asm!("sti; hlt", options(nomem, nostack, preserves_flags)); }
    }
}

/// Variant of this fn that stamps explicit
/// `vtgid` / `vtid` on the spawned task before it's enqueued.
/// Used by the PID 1 spawn path to make `getpid()` /
/// `set_tid_address()` report Linux PID 1 from the very first
/// syscall (musl crt1's `__init_main_thread` caches the
/// set_tid_address return as `__libc.tid`).
///
/// # SAFETY: same preconditions as this fn.
/// # C: O(phdrs) parse + O(log N) enqueue
unsafe fn spawn_user_blob_with_vpid(
    blob:      &'static [u8],
    name:      &'static str,
    tid:       u32,
    vpid_tgid: u32,
    vpid_tid:  u32,
    argv:      &[&[u8]],
) {
    use vmm::{AddressSpace, VmaBacking, VmaFlags, VmaProt};
    use hal::{MmuOps, UserVirtAddr};

    // Fresh per-task AS so back-to-back smokes don't overlap PIE
    // pages. Kernel-half is shared (entries 256..512 copied from
    // the master PML4); user-half starts empty.
    // SAFETY: post-PMM init; new_user_pml4 returns a freshly
    // allocated frame zeroed + populated with the kernel half.
    let root_pa = match unsafe { hal_x86_64::mmu_ops::new_user_pml4() } {
        Some(p) => p,
        None    => {
            debug_irq! { klog::kerror!("user-blob: new_user_pml4 failed"); }
            return;
        }
    };
    let mm = match AddressSpace::new(root_pa) {
        Ok(a)  => a,
        Err(_) => {
            debug_irq! { klog::kerror!("user-blob: AddressSpace::new failed"); }
            return;
        }
    };

    // Activate the new AS BEFORE load_static_blob — that function
    // applies DT_RELA self-relocations by writing through user
    // VAs (e.g. 0x10003000 GOT slots). Those writes only land
    // in the right page table if the task's AS is the active CR3;
    // otherwise the kernel page-faults on a not-present user page
    // in whatever AS happened to be active. Pre-fix this worked
    // by luck when the previous task's AS had compatible pages
    // mapped at the same VAs.
    // SAFETY: per-AS PML4 was constructed with kernel-half shared from master so kernel mappings remain valid; CR3 swap legal at CPL=0 IRQ-off.
    unsafe { <hal_x86_64::mmu_ops::X86Mmu as MmuOps>::activate(root_pa); }

    #[cfg(feature = "debug-boot")]
    {
        klog::write_raw(b"[INFO]  user-blob: load begin ");
        klog::write_raw(name.as_bytes());
        klog::write_raw(b"\n");
    }
    let img = match (|| -> Result<_, elf_load::LoadError> {
        let img = load_static_blob(blob, &mm)?;
        let stack_hint = UserVirtAddr::new(USER_STACK_VA)
            .ok_or(elf_load::LoadError::Einval)?;
        mm.mmap(
            Some(stack_hint), USER_STACK_LEN as usize,
            VmaProt::READ | VmaProt::WRITE,
            VmaFlags::PRIVATE | VmaFlags::ANONYMOUS,
            VmaBacking::Anonymous,
            true,
        ).map_err(|_| elf_load::LoadError::Enomem)?;
        // F152-2: no kernel-side TLS region — user crt1 mmaps its
        // own TCB and installs FS_BASE via arch_prctl(ARCH_SET_FS).
        Ok(img)
    })() {
        Ok(i)  => i,
        Err(e) => {
            #[cfg(feature = "debug-boot")]
            {
                klog::write_raw(b"[ERROR] user-blob load failed: ");
                klog::write_raw(name.as_bytes());
                klog::write_raw(b" err=");
                klog::write_raw(match e {
                    elf_load::LoadError::Enoexec => b"Enoexec",
                    elf_load::LoadError::Einval => b"Einval",
                    elf_load::LoadError::Enomem => b"Enomem",
                });
                klog::write_raw(b"\n");
            }
            return;
        }
    };
    #[cfg(feature = "debug-boot")]
    klog::write_raw(b"[INFO]  user-blob: load ok\n");

    let random16 = {
        use hal::TimerOps;
        let ns = hal_x86_64::X86TimerOps::monotonic_ns().0;
        let mut r = [0u8; 16];
        for i in 0..16 { r[i] = (ns >> ((i % 8) * 8)) as u8 ^ (i as u8 * 0x9b); }
        r
    };
    // setup_arg_pages: eagerly map the initial stack into the new AS so the
    // stack build below doesn't demand-fault in boot context (current()==None).
    pmm::user_as::prefault_stack(&mm, USER_STACK_TOP, USER_STACK_LEN);
    #[cfg(feature = "debug-boot")]
    klog::write_raw(b"[INFO]  user-blob: stack prefault ok\n");
    // Default argv = ['/init']; otherwise caller-provided.
    let default_argv: &[&[u8]] = &[b"/init"];
    let argv_ref: &[&[u8]] = if argv.is_empty() { default_argv } else { argv };
    // SAFETY: per-task AS just activated; build_user_stack writes through it; demand-fault resolves the new stack page.
    let new_sp = unsafe {
        elf_load::stack::build_user_stack(
            USER_STACK_TOP,
            argv_ref, &[b"TERM=vt100" as &[u8]],
            &img,
            &random16,
            argv_ref.first().copied().unwrap_or(b""),
            0, // smoke: no vDSO mapped
            <hal_x86_64::X86CpuOps as hal::CpuOps>::cpu_hwcap(),
        )
    }.map(|l| l.sp).unwrap_or(USER_STACK_TOP);
    #[cfg(feature = "debug-boot")]
    klog::write_raw(b"[INFO]  user-blob: stack build ok\n");

    // SAFETY: runqueue installed; mm matches active CR3; entry/sp in user range; vpid stamped pre-enqueue so musl's __init_main_thread sees PID 1 on its very first syscall.
    let task = match unsafe {
        sched::live::spawn_user_thread_with_vpid(
            tid, vpid_tgid, vpid_tid, name, img.user_ip(), new_sp, mm,
        )
    } {
        Ok(t)  => t,
        Err(_) => {
            #[cfg(feature = "debug-boot")]
            klog::write_raw(b"[ERROR] user-blob: spawn failed\n");
            return;
        }
    };
    #[cfg(feature = "debug-boot")]
    klog::write_raw(b"[INFO]  user-blob: spawn ok\n");

    let fdt = console::init_console_fd_table();
    // SAFETY: task isn't yet scheduled; we are sole writer.
    unsafe { task.replace_fd_table(Some(fdt)); }
    let _task = task;

    // F152-2: leave FS_BASE = 0 on first user entry. musl crt1's
    // __init_tls calls arch_prctl(ARCH_SET_FS, tcb) before any
    // FS-relative access, matching Linux execve semantics.
    // SAFETY: wrmsr IA32_FS_BASE = 0 at CPL=0 is legal; user crt1
    // overwrites with the real TCB before first FS-relative load.
    unsafe { hal_x86_64::set_user_fs_base(0); }

    debug_irq! {
        klog::write_raw(b"[INFO]  user-blob: spawned name=");
        klog::write_raw(name.as_bytes());
        klog::write_raw(b"\n");
    }

    // schedule() into the user task. Returns to the boot anchor
    // when (a) the task exits via sys_exit, or (b) the task
    // parks (e.g. blocks on `read`) and no other runnable task
    // is on this CPU's runqueue. In case (b), run_as_task's
    // schedule-forever loop (IRQs on) keeps timer IRQs firing for deadlines;
    // UART RX wakeups arrive through the owning serial IRQ handler.
    // SAFETY: process ctx; runqueue installed; preempt-off.
    unsafe { sched::live::schedule(); }
}
