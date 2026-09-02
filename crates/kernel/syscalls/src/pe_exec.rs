//! PE task commit for the W1 no-Win32 entry path.

#![cfg(target_os = "oxide-kernel")]

#[cfg(target_arch = "x86_64")]
use hal::MmuOps;
#[cfg(target_arch = "x86_64")]
use hal::CpuOps;

/// `None` means the image is not PE. `Some(Ok(()))` commits the PE task;
/// `Some(Err(errno))` means it was PE but could not be committed.
/// # C: O(image + N_vmas)
pub fn try_commit(cur: &sched::Task, path: &[u8], blob: &[u8], exec_vp: Option<&vfs::VfsPath>) -> Option<Result<(), i64>> {
    if !matches!(elf_load::format::identify(blob), elf_load::format::BinaryFormat::Pe) { return None; }
    #[cfg(target_arch = "x86_64")]
    { Some(commit_x86(cur, path, blob, exec_vp, None)) }
    #[cfg(target_arch = "aarch64")]
    { let _ = (cur, path, blob, exec_vp); Some(Err(-(syscall::errno::Errno::Enoexec.as_i32() as i64))) }
}

#[cfg(target_os = "oxide-kernel")]
pub fn try_commit_with_catalog(cur: &sched::Task, path: &[u8], blob: &[u8], catalog: &pe::catalog::ModuleCatalog) -> Result<(), i64> {
    #[cfg(target_arch = "x86_64")]
    { commit_x86(cur, path, blob, None, Some(catalog)) }
    #[cfg(target_arch = "aarch64")]
    { let _ = (cur, path, blob, catalog); Err(-(syscall::errno::Errno::Enoexec.as_i32() as i64)) }
}

#[cfg(target_arch = "x86_64")]
fn commit_x86(cur: &sched::Task, path: &[u8], blob: &[u8], exec_vp: Option<&vfs::VfsPath>, catalog: Option<&pe::catalog::ModuleCatalog>) -> Result<(), i64> {
    use vmm::{AddressSpace, VmaBacking, VmaProt};
    // Linux's default initial user stack mapping is eight MiB. Wine's loader
    // legitimately uses substantially more than the PE ABI shadow space while
    // constructing process state, so the NT path must provide the same stack
    // extent as ELF exec rather than a tiny bootstrap-only VMA.
    const STACK_BYTES: usize = 8 * 1024 * 1024;
    let enoexec = || -(syscall::errno::Errno::Enoexec.as_i32() as i64);
    let root = unsafe { hal_x86_64::mmu_ops::new_user_pml4() }.ok_or_else(|| nomem(b"[WINDOWS-PE-NOMEM] pml4\n"))?;
    let old = unsafe { cur.mm_ref() }.cloned();
    let as_ = match old.as_ref() { Some(old) => AddressSpace::new_for_exec(root, old), None => AddressSpace::new(root) }
        .map_err(|_| nomem(b"[WINDOWS-PE-NOMEM] address-space\n"))?;
    // Linux installs the address-space teardown owner before any user VMA is
    // created.  PE exec is a second image-loading entry point, so it must use
    // the same lifetime contract as ELF exec or anonymous pages cannot be
    // reclaimed through the normal mm exit path.
    pmm::user_as::install_teardown(&as_);
    // Linux arms the per-exec mmap anchor before get_unmapped_area is used.
    // Keep PE placement on the same ASLR/layout contract as ELF while retaining
    // the small initial PE stack used by this bootstrap path.
    let rnd = crate::exec_transition::exec_rnd(cur, 0);
    as_.set_mmap_layout(rnd.mmap_base(STACK_BYTES as u64), true);
    let stack_hint = hal::UserVirtAddr::new(rnd.stack_top().saturating_sub(STACK_BYTES as u64))
        .ok_or_else(|| nomem(b"[WINDOWS-PE-NOMEM] stack-address\n"))?;
    let stack = as_.mmap(Some(stack_hint), STACK_BYTES, VmaProt::READ | VmaProt::WRITE,
        vmm::EXEC_STACK_VMA_FLAGS, VmaBacking::Anonymous, false).map_err(|_| nomem(b"[WINDOWS-PE-NOMEM] stack\n"))?;
    let stack_top = stack.as_u64().checked_add(STACK_BYTES as u64).ok_or_else(|| nomem(b"[WINDOWS-PE-NOMEM] stack-overflow\n"))?;
    let path = core::str::from_utf8(path).map_err(|_| enoexec())?;
    let mut creds = crate::exec_transition::decide(cur, exec_vp).map_err(|e| -(e.as_i32() as i64))?;
    let selinux = crate::exec_transition::selinux_decide(cur, exec_vp).map_err(|e| -(e.as_i32() as i64))?;
    creds.secure_exec |= selinux.secure_exec;
    let input = elf_load::process_env::EnvironmentInput {
        image_base: 0, image_size: 0, image_path: path, command_line: path,
        environment: &[], process_id: cur.tgid.load(core::sync::atomic::Ordering::Acquire), thread_id: cur.tid,
    };
    let runtime = elf_load::pe_loader::map_nt_runtime(&as_).map_err(|_| enoexec())?;
    let runtime_module = elf_load::process_env::NtModuleInput {
        base: runtime.base.as_u64(), entry: 0, size: runtime.bytes as u32,
        full_name: "C:\\Windows\\System32\\ntdll.dll", base_name: "ntdll.dll",
    };
    let process = match catalog.map_or_else(
        || elf_load::pe_loader::load_pe_process_with_resolver_and_modules(blob, &as_, &input, stack_top, &runtime, &[runtime_module]),
        |catalog| elf_load::pe_loader::load_pe_process_with_catalog(blob, &as_, &input, stack_top, &runtime, catalog),
    ) {
        Ok(process) => process,
        Err(_) => {
            let _ = as_.munmap(runtime.base, runtime.bytes);
            return Err(enoexec());
        }
    };
    // Diagnostic experiment for the AMD64 relay first-touch failure: populate
    // executable PE/runtime pages before the first user instruction. This is
    // deliberately feature-gated; if it changes the failure, the permanent
    // fix belongs in the fault/PTE retry path rather than here.
    #[cfg(feature = "debug-faultdiag")]
    for vma in as_.snapshot_vmas() {
        if !vma.prot.contains(VmaProt::EXEC) || !matches!(vma.backing, VmaBacking::KernelBytes { .. }) { continue; }
        pmm::user_as::prefault_user_range_with_access(
            &as_, vma.start.as_u64(), vma.end.as_u64() - vma.start.as_u64(), vmm::FaultAccess::Exec,
        ).map_err(|_| enoexec())?;
    }
    // Validate the only live-task mutation target before activating or
    // publishing the replacement address space. A missing frame is a failed
    // commit, so the caller must retain its Linux mm and personality.
    let regs = hal_x86_64::current_pt_regs();
    if regs.is_null() { return Err(nomem(b"[WINDOWS-PE-NOMEM] regs\n")); }
    let cpu = (hal_x86_64::X86CpuOps::current_cpu() as usize).min(cpu::MAX_CPUS - 1);
    as_.mark_cpu(cpu);
    // SAFETY: root belongs to this freshly-built address space and activation
    // occurs before the task publishes the replacement mm.
    unsafe { <hal_x86_64::mmu_ops::X86Mmu as MmuOps>::activate(root); }
    if let Some(old) = unsafe { cur.mm_ref() } { old.clear_cpu(cpu); }
    // SAFETY: this is the running task's unpublished exec replacement under
    // the same single-mutator invariant as the existing ELF exec path.
    unsafe { cur.replace_mm(Some(as_)); }
    // SAFETY: the PE environment owns the TEB address and this task's context
    // is exclusively writable during the exec commit.
    unsafe {
        hal_x86_64::set_user_gs_base(process.entry.gs_base.as_u64());
        let ctx = cur.arch_ctx_ptr::<hal_x86_64::ContextX86_64>();
        (*ctx).gs_base = process.entry.gs_base.as_u64();
    }
    cur.set_nt_personality(true);
    cur.set_nt_peb(process.environment.peb.as_u64());
    cur.set_nt_teb(process.environment.teb.as_u64());
    crate::exec_transition::commit(cur, &creds);
    crate::exec_transition::selinux_commit(cur, &selinux);
    super::execve_common::reset_caught_signals(cur);
    super::execve_common::reset_per_execve_state(cur);
    cur.set_comm_exec(path.rsplit('/').next().unwrap_or(path));
    // SAFETY: current_pt_regs is the live syscall frame of this running task;
    // the exec path owns it until the common return-to-user epilogue.
    let frame = unsafe { &mut *regs };
    klog::write_raw(b"[WINDOWS-PE-START] entry=");
    klog::write_hex_u64(process.entry.rip.as_u64());
    klog::write_raw(b" rsp=");
    klog::write_hex_u64(process.entry.rsp.as_u64());
    klog::write_raw(b" stack=");
    klog::write_hex_u64(stack.as_u64());
    klog::write_raw(b"-");
    klog::write_hex_u64(stack_top);
    klog::write_raw(b"\n");
    *frame = hal_x86_64::PtRegs { rip: process.entry.rip.as_u64(), rsp: process.entry.rsp.as_u64(), rflags: 0x202,
        cs: hal_x86_64::USER_CS_SELECTOR, ss: hal_x86_64::USER_SS_SELECTOR,
        vector: frame.vector, error: frame.error, ..Default::default() };
    sched::live::vfork_done(cur);
    klog::write_raw(b"[WINDOWS-PE-COMMIT] success\n");
    Ok(())
}

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
fn nomem(message: &'static [u8]) -> i64 {
    klog::write_raw(message);
    -(syscall::errno::Errno::Enomem.as_i32() as i64)
}
