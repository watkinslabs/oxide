//! PE task commit for the W1 no-Win32 entry path.

#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;
#[cfg(target_arch = "x86_64")]
use alloc::{format, vec, vec::Vec};

#[cfg(target_arch = "x86_64")]
use hal::MmuOps;
#[cfg(target_arch = "x86_64")]
use hal::CpuOps;
#[cfg(all(target_arch = "x86_64", feature = "debug-faultdiag"))]
use vmm::{VmaBacking, VmaProt};

#[cfg(target_arch = "x86_64")]
pub struct PreparedPeProcess {
    pub mm: alloc::sync::Arc<vmm::AddressSpace>,
    pub stack: hal::UserVirtAddr,
    pub stack_top: u64,
    pub process: elf_load::pe_loader::PeProcess,
    pub initial_entry: u64,
    pub initial_stack: u64,
}

/// Private PE launch continuation. The mapped image, environment, and
/// single-use startup transaction stay unpublished until the caller has
/// completed every fallible exec/child preparation step. Dropping it is the
/// rollback for a failed launch: the private address space loses its last Arc
/// and the mapped image is never installed in the task.
#[cfg(target_arch = "x86_64")]
pub(crate) struct PeLaunchContinuation { prepared: Option<PreparedPeProcess> }

#[cfg(target_arch = "x86_64")]
impl PeLaunchContinuation {
    pub(crate) fn new(prepared: PreparedPeProcess) -> Result<Self, i64> {
        if prepared.process.startup.personality != elf_load::pe_loader::ExecutionPersonality::Nt {
            return Err(-(syscall::errno::Errno::Enoexec.as_i32() as i64));
        }
        Ok(Self { prepared: Some(prepared) })
    }
    pub(crate) fn prepared(&self) -> &PreparedPeProcess { self.prepared.as_ref().expect("launch continuation present") }
    pub(crate) fn startup(&self) -> &elf_load::pe_startup::PeStartupFacts { self.prepared().process.startup.facts() }
    pub(crate) fn take(mut self) -> (PreparedPeProcess, elf_load::pe_startup::PeStartupFacts) {
        let prepared = self.prepared.take().expect("launch continuation present");
        let startup = prepared.process.startup.finish();
        (prepared, startup)
    }
}

#[cfg(target_arch = "x86_64")]
fn select_nt_personality(task: &sched::Task, startup: &elf_load::pe_startup::PeStartupFacts) -> Result<(), i64> {
    if startup.personality != elf_load::pe_loader::ExecutionPersonality::Nt { return Err(-(syscall::errno::Errno::Enoexec.as_i32() as i64)); }
    task.set_nt_personality(true);
    Ok(())
}

#[cfg(target_arch = "x86_64")]
struct NtStandardHandles {
    params: elf_load::process_env::NtProcessParameters<'static>,
    handles: [sched::nt_object::NtHandle; 3],
}

#[cfg(target_arch = "x86_64")]
impl NtStandardHandles {
    fn close(self, table: &sched::nt_object::NtHandleTable) {
        for handle in self.handles { let _ = table.close(handle); }
    }
}

/// Wrap the invoking Linux fd 0/1/2 descriptions as inherited NT file
/// objects. The NT process parameters point at these same VFS open
/// descriptions; no second console or output buffer is created.
#[cfg(target_arch = "x86_64")]
fn inherit_nt_standard_handles(cur: &sched::Task) -> Option<NtStandardHandles> {
    const FILE_READ_DATA: u32 = 0x0001;
    const FILE_WRITE_DATA: u32 = 0x0002;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    let fdt = cur.clone_fd_table()?;
    let files = [fdt.get(0).ok()?, fdt.get(1).ok()?, fdt.get(2).ok()?];
    if !files[0].f_mode().contains(vfs::Fmode::READ)
        || !files[1].f_mode().contains(vfs::Fmode::WRITE)
        || !files[2].f_mode().contains(vfs::Fmode::WRITE) { return None; }
    let table = cur.thread_group.nt_handles();
    let access = [FILE_READ_DATA | SYNCHRONIZE, FILE_WRITE_DATA | SYNCHRONIZE, FILE_WRITE_DATA | SYNCHRONIZE];
    let mut handles = [sched::nt_object::NtHandle::invalid(); 3];
    for index in 0..3 {
        let handle = table.insert(table.new_file(files[index].clone()), access[index]);
        let Some(handle) = handle else {
            for previous in handles.into_iter().filter(|handle| *handle != sched::nt_object::NtHandle::invalid()) { let _ = table.close(previous); }
            return None;
        };
        handles[index] = handle;
    }
    let raw = handles.map(|handle| handle.raw() as u64);
    Some(NtStandardHandles { params: elf_load::process_env::NtProcessParameters {
        current_directory: "C:\\Windows", current_directory_handle: 0,
        console_handle: raw[1], standard_handles: raw,
    }, handles })
}

/// `None` means the image is not PE. `Some(Ok(()))` commits the PE task;
/// `Some(Err(errno))` means it was PE but could not be committed.
/// # C: O(image + N_vmas)
pub fn try_commit(cur: &sched::Task, path: &[u8], blob: &[u8], exec_vp: Option<&vfs::VfsPath>) -> Option<Result<(), i64>> {
    if !matches!(elf_load::format::identify(blob), elf_load::format::BinaryFormat::Pe) { return None; }
    #[cfg(target_arch = "x86_64")]
    { Some(commit_x86(cur, path, blob, exec_vp, None, None, &[], None)) }
    #[cfg(target_arch = "aarch64")]
    { let _ = (cur, path, blob, exec_vp); Some(Err(-(syscall::errno::Errno::Enoexec.as_i32() as i64))) }
}

#[cfg(target_os = "oxide-kernel")]
#[allow(dead_code)]
pub fn try_commit_with_catalog(cur: &sched::Task, path: &[u8], blob: &[u8], catalog: &pe::catalog::ModuleCatalog) -> Result<(), i64> {
    try_commit_with_catalog_and_environment(cur, path, blob, catalog, core::str::from_utf8(path).unwrap_or(""), &[])
}

#[cfg(target_os = "oxide-kernel")]
#[allow(dead_code)]
pub fn try_commit_with_catalog_and_command_line(cur: &sched::Task, path: &[u8], blob: &[u8], catalog: &pe::catalog::ModuleCatalog, command_line: &str) -> Result<(), i64> {
    try_commit_with_catalog_and_environment(cur, path, blob, catalog, command_line, &[])
}

#[cfg(target_os = "oxide-kernel")]
pub fn try_commit_with_catalog_and_environment(cur: &sched::Task, path: &[u8], blob: &[u8], catalog: &pe::catalog::ModuleCatalog, command_line: &str, environment: &[(String, String)]) -> Result<(), i64> {
    try_commit_with_catalog_and_environment_and_bootstrap(cur, path, blob, catalog, command_line, environment, None)
}

#[cfg(target_os = "oxide-kernel")]
pub fn try_commit_with_catalog_and_environment_and_bootstrap(cur: &sched::Task, path: &[u8], blob: &[u8], catalog: &pe::catalog::ModuleCatalog, command_line: &str, environment: &[(String, String)], bootstrap: Option<&[u8]>) -> Result<(), i64> {
    #[cfg(target_arch = "x86_64")]
    {
        let environment_refs: alloc::vec::Vec<(&str, &str)> = environment.iter().map(|(name, value)| (name.as_str(), value.as_str())).collect();
        commit_x86(cur, path, blob, None, Some(catalog), Some(command_line), &environment_refs, bootstrap)
    }
    #[cfg(target_arch = "aarch64")]
    { let _ = (cur, path, blob, catalog, command_line, environment, bootstrap); Err(-(syscall::errno::Errno::Enoexec.as_i32() as i64)) }
}

#[cfg(target_arch = "x86_64")]
fn commit_x86(cur: &sched::Task, path: &[u8], blob: &[u8], exec_vp: Option<&vfs::VfsPath>, catalog: Option<&pe::catalog::ModuleCatalog>, command_line: Option<&str>, environment: &[(&str, &str)], bootstrap: Option<&[u8]>) -> Result<(), i64> {
    let enoexec = || -(syscall::errno::Errno::Enoexec.as_i32() as i64);
    let table = cur.thread_group.nt_handles();
    let mut stdio = inherit_nt_standard_handles(cur);
    let params = stdio.as_ref().map(|stdio| &stdio.params);
    let prepared = match prepare_pe_process(cur, path, blob, command_line, environment, params, exec_vp, catalog,
        cur.tgid.load(core::sync::atomic::Ordering::Acquire), cur.tid, true, bootstrap) {
        Ok(prepared) => prepared,
        Err(error) => { close_stdio(&mut stdio, &table); return Err(error); },
    };
    let continuation = match PeLaunchContinuation::new(prepared) { Ok(value) => value, Err(error) => { close_stdio(&mut stdio, &table); return Err(error); } };
    let path = match core::str::from_utf8(path) { Ok(path) => path, Err(_) => { close_stdio(&mut stdio, &table); return Err(enoexec()); } };
    let mut creds = match decide_exec_box(cur, exec_vp) { Ok(creds) => creds, Err(error) => { close_stdio(&mut stdio, &table); return Err(error); } };
    let selinux = match decide_selinux_box(cur, exec_vp) { Ok(selinux) => selinux, Err(error) => { close_stdio(&mut stdio, &table); return Err(error); } };
    creds.secure_exec |= selinux.secure_exec;
    // Diagnostic experiment for the AMD64 relay first-touch failure: populate
    // executable PE/runtime pages before the first user instruction. This is
    // deliberately feature-gated; if it changes the failure, the permanent
    // fix belongs in the fault/PTE retry path rather than here.
    #[cfg(feature = "debug-faultdiag")]
    let as_ = &continuation.prepared().mm;
    #[cfg(feature = "debug-faultdiag")]
    for vma in as_.snapshot_vmas() {
        if !vma.prot.contains(VmaProt::EXEC) || !matches!(vma.backing, VmaBacking::KernelBytes { .. }) { continue; }
        pmm::user_as::prefault_user_range_with_access(
            as_, vma.start.as_u64(), vma.end.as_u64() - vma.start.as_u64(), vmm::FaultAccess::Exec,
        ).map_err(|_| { close_stdio(&mut stdio, &table); enoexec() })?;
    }
    // Validate the only live-task mutation target before activating or
    // publishing the replacement address space. A missing frame is a failed
    // commit, so the caller must retain its Linux mm and personality.
    let regs = hal_x86_64::current_pt_regs();
    if regs.is_null() { close_stdio(&mut stdio, &table); return Err(nomem(b"[WINDOWS-PE-NOMEM] regs\n")); }
    let startup_view = continuation.prepared().process.startup.facts();
    if let Err(error) = select_nt_personality(cur, startup_view) { close_stdio(&mut stdio, &table); return Err(error); }
    let (prepared, startup) = continuation.take();
    let PreparedPeProcess { mm: as_, stack, stack_top, process, initial_entry, initial_stack } = prepared;
    let cpu = (hal_x86_64::X86CpuOps::current_cpu() as usize).min(cpu::MAX_CPUS - 1);
    as_.mark_cpu(cpu);
    // SAFETY: root belongs to this freshly-built address space and activation
    // occurs before the task publishes the replacement mm.
    unsafe { <hal_x86_64::mmu_ops::X86Mmu as MmuOps>::activate(as_.root_pa()); }
    if let Some(old) = unsafe { cur.mm_ref() } { old.clear_cpu(cpu); }
    // SAFETY: this is the running task's unpublished exec replacement under
    // the same single-mutator invariant as the existing ELF exec path.
    unsafe { cur.replace_mm(Some(as_)); }
    // SAFETY: the PE environment owns the TEB address and this task's context
    // is exclusively writable during the exec commit.
    unsafe {
        hal_x86_64::set_user_gs_base(startup.gs_base.as_u64());
        let ctx = cur.arch_ctx_ptr::<hal_x86_64::ContextX86_64>();
        (*ctx).gs_base = startup.gs_base.as_u64();
    }
    sched::initialize_current_process(cur);
    cur.set_nt_peb(process.environment.peb.as_u64());
    cur.set_nt_teb(process.environment.teb.as_u64());
    crate::exec_transition::commit(cur, &creds);
    crate::exec_transition::selinux_commit(cur, &selinux);
    super::execve_common::reset_caught_signals(cur);
    super::execve_common::reset_per_execve_state(cur);
    cur.set_comm_exec(crate::nt_process_naming::comm_of(path));
    // This task was the Linux launcher a moment ago; without these its procfs
    // identity still describes that launcher, not the image now running in it.
    // `exec_vp` is the pinned host file this exec actually resolved, so `exe`
    // is published only when one exists rather than from the request's name.
    if let Some(command_line) = command_line.filter(|line| !line.is_empty()) {
        cur.set_cmdline(Some(alloc::string::String::from(command_line)));
    }
    if exec_vp.is_some() {
        cur.set_exe_path(Some(alloc::string::String::from(path)));
        // SAFETY: the replacement mm was installed above by this exec commit and
        // no concurrent exec can replace it while identity is being published.
        if let Some(mm) = unsafe { cur.mm_ref() } { mm.set_exe_path(alloc::string::String::from(path)); }
    }
    // SAFETY: current_pt_regs is the live syscall frame of this running task;
    // the exec path owns it until the common return-to-user epilogue.
    let frame = unsafe { &mut *regs };
    crate::nt_milestone::reset();
    klog::write_raw(b"[WINDOWS-PE-START] entry=");
    klog::write_hex_u64(initial_entry);
    klog::write_raw(b" rsp=");
    klog::write_hex_u64(initial_stack);
    klog::write_raw(b" stack=");
    klog::write_hex_u64(stack.as_u64());
    klog::write_raw(b"-");
    klog::write_hex_u64(stack_top);
    klog::write_raw(b"\n");
    *frame = hal_x86_64::PtRegs { rip: initial_entry, rsp: initial_stack, rflags: 0x202,
        cs: hal_x86_64::USER_CS_SELECTOR, ss: hal_x86_64::USER_SS_SELECTOR,
        vector: frame.vector, error: frame.error, ..Default::default() };
    sched::live::vfork_done(cur);
    klog::write_raw(b"[WINDOWS-PE-COMMIT] success\n");
    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn close_stdio(stdio: &mut Option<NtStandardHandles>, table: &sched::nt_object::NtHandleTable) {
    if let Some(handles) = stdio.take() { handles.close(table); }
}

#[cfg(target_arch = "x86_64")]
#[inline(never)]
fn decide_exec_box(cur: &sched::Task, file: Option<&vfs::VfsPath>) -> Result<alloc::boxed::Box<crate::exec_creds::ExecTransition>, i64> {
    crate::exec_transition::decide(cur, file).map(alloc::boxed::Box::new).map_err(|e| -(e.as_i32() as i64))
}

#[cfg(target_arch = "x86_64")]
#[inline(never)]
fn decide_selinux_box(cur: &sched::Task, file: Option<&vfs::VfsPath>) -> Result<alloc::boxed::Box<sched::selinux_label::ExecPlan>, i64> {
    crate::exec_transition::selinux_decide(cur, file).map(alloc::boxed::Box::new).map_err(|e| -(e.as_i32() as i64))
}

#[cfg(target_arch = "x86_64")]
#[inline(never)]
fn map_nt_runtime_box(as_: &vmm::AddressSpace) -> Result<alloc::boxed::Box<elf_load::pe_loader::NtRuntime>, pe::Error> {
    elf_load::pe_loader::map_nt_runtime(as_).map(alloc::boxed::Box::new)
}

#[cfg(target_arch = "x86_64")]
#[inline(never)]
fn build_pe_address_space(cur: &sched::Task, stack_bytes: usize, replace_current: bool) -> Result<(alloc::sync::Arc<vmm::AddressSpace>, hal::UserVirtAddr, u64), i64> {
    let root = unsafe { hal_x86_64::mmu_ops::new_user_pml4() }.ok_or_else(|| nomem(b"[WINDOWS-PE-NOMEM] pml4\n"))?;
    let old = unsafe { cur.mm_ref() }.cloned();
    let as_ = match (replace_current, old.as_ref()) {
        (true, Some(old)) => vmm::AddressSpace::new_for_exec(root, old),
        _ => vmm::AddressSpace::new(root),
    }
        .map_err(|_| nomem(b"[WINDOWS-PE-NOMEM] address-space\n"))?;
    pmm::user_as::install_teardown(&as_);
    let rnd = crate::exec_transition::exec_rnd(cur, 0);
    as_.set_mmap_layout(rnd.mmap_base(stack_bytes as u64), true);
    let stack_hint = hal::UserVirtAddr::new(rnd.stack_top().saturating_sub(stack_bytes as u64))
        .ok_or_else(|| nomem(b"[WINDOWS-PE-NOMEM] stack-address\n"))?;
    let stack = as_.mmap(Some(stack_hint), stack_bytes, vmm::VmaProt::READ | vmm::VmaProt::WRITE,
        vmm::EXEC_STACK_VMA_FLAGS, vmm::VmaBacking::Anonymous, false).map_err(|_| nomem(b"[WINDOWS-PE-NOMEM] stack\n"))?;
    let stack_top = stack.as_u64().checked_add(stack_bytes as u64).ok_or_else(|| nomem(b"[WINDOWS-PE-NOMEM] stack-overflow\n"))?;
    Ok((as_, stack, stack_top))
}

/// Prepare a complete PE process image without publishing a task. Exec uses
/// `replace_current = true`; native child creation uses `false` and receives a
/// fresh address space. # C: O(image + N_vmas)
#[cfg(target_arch = "x86_64")]
pub fn prepare_pe_process(cur: &sched::Task, path: &[u8], blob: &[u8], command_line: Option<&str>, environment: &[(&str, &str)], params: Option<&elf_load::process_env::NtProcessParameters<'_>>, _exec_vp: Option<&vfs::VfsPath>, catalog: Option<&pe::catalog::ModuleCatalog>, process_id: u32, thread_id: u32, replace_current: bool, bootstrap: Option<&[u8]>) -> Result<PreparedPeProcess, i64> {
    const STACK_BYTES: usize = 8 * 1024 * 1024;
    let enoexec = || -(syscall::errno::Errno::Enoexec.as_i32() as i64);
    let path = core::str::from_utf8(path).map_err(|_| enoexec())?;
    let (as_, stack, stack_top) = build_pe_address_space(cur, STACK_BYTES, replace_current)?;
    let runtime = map_nt_runtime_box(&as_).map_err(|_| enoexec())?;
    let runtime_module = elf_load::process_env::NtModuleInput {
        base: runtime.base.as_u64(), entry: 0, size: runtime.bytes as u32,
        full_name: "C:\\Windows\\System32\\ntdll.dll", base_name: "ntdll.dll",
    };
    let input = elf_load::process_env::EnvironmentInput {
        image_base: 0, image_size: 0, image_path: path,
        command_line: command_line.unwrap_or(path), environment, process_id, thread_id,
    };
    let process = match catalog.map_or_else(
        || elf_load::pe_loader::load_pe_process_with_resolver_and_modules_and_params_with_stack_bounds(blob, &as_, &input, stack.as_u64(), stack_top, &*runtime, &[runtime_module], params),
        |catalog| elf_load::pe_loader::load_pe_process_with_catalog_and_params_with_stack_bounds(blob, &as_, &input, stack.as_u64(), stack_top, &runtime, catalog, params),
    ) {
        Ok(process) => process,
        Err(_) => {
            let _ = as_.munmap(runtime.base, runtime.bytes);
            return Err(enoexec());
        }
    };
    let startup = process.startup.facts();
    let rnd = crate::exec_transition::exec_rnd(cur, 0);
    let (initial_entry, initial_stack) = match bootstrap {
        Some(blob) => prepare_native_bootstrap(&as_, blob, environment, startup.transfer_entry.as_u64(), startup.stack_pointer.as_u64(), startup.teb.as_u64(), startup.peb.as_u64(), &rnd, enoexec())?,
        None => (startup.transfer_entry.as_u64(), startup.stack_pointer.as_u64()),
    };
    Ok(PreparedPeProcess { mm: as_, stack, stack_top, initial_entry, initial_stack, process })
}

#[cfg(target_arch = "x86_64")]
fn prepare_native_bootstrap(
    as_: &alloc::sync::Arc<vmm::AddressSpace>,
    blob: &[u8],
    environment: &[(&str, &str)],
    pe_entry: u64,
    pe_stack: u64,
    teb: u64,
    peb: u64,
    rnd: &aslr::ExecRnd,
    enoexec: i64,
) -> Result<(u64, u64), i64> {
    const BOOTSTRAP_STACK_BYTES: usize = 2 * 1024 * 1024;
    let stack = as_.mmap(None, BOOTSTRAP_STACK_BYTES, vmm::VmaProt::READ | vmm::VmaProt::WRITE,
        vmm::EXEC_STACK_VMA_FLAGS, vmm::VmaBacking::Anonymous, false).map_err(|_| enoexec)?;
    let stack_top = stack.as_u64().checked_add(BOOTSTRAP_STACK_BYTES as u64).ok_or(enoexec)?;
    let image = match elf_load::load_image(elf_load::Image::embedded(blob), None, as_, rnd) {
        Ok(image) => image,
        Err(error) => {
            log_bootstrap_failure(b"elf-load", error);
            return Err(enoexec);
        }
    };
    let argv_storage = vec![b"windows-runtime".to_vec(), b"--native-bootstrap".to_vec()];
    let mut env_storage: Vec<Vec<u8>> = environment.iter().map(|(name, value)| format!("{name}={value}").into_bytes()).collect();
    env_storage.push(format!("OXIDE_PE_ENTRY=0x{pe_entry:x}").into_bytes());
    env_storage.push(format!("OXIDE_PE_STACK=0x{pe_stack:x}").into_bytes());
    // The source-owned Wine adapter uses these canonical Oxide addresses to
    // attach its existing thread_data record before any native constructor
    // calls NtCurrentTeb(). They are bootstrap-only inputs, not a replacement
    // for the kernel's GS/TEB publication.
    env_storage.push(format!("OXIDE_NT_TEB=0x{teb:x}").into_bytes());
    env_storage.push(format!("OXIDE_NT_PEB=0x{peb:x}").into_bytes());
    let argv: Vec<&[u8]> = argv_storage.iter().map(|value| value.as_slice()).collect();
    let envp: Vec<&[u8]> = env_storage.iter().map(|value| value.as_slice()).collect();
    let plan = match elf_load::stack::plan_initial_stack(stack_top, BOOTSTRAP_STACK_BYTES as u64, &argv, &envp, rnd) {
        Some(plan) => plan,
        None => {
            klog::write_raw(b"[WINDOWS-PE-BOOTSTRAP-FAIL] stage=stack-plan\n");
            return Err(enoexec);
        }
    };
    let random16 = crate::auxrandom::at_random_bytes();
    // The generic prefault path resolves pages through the active MmuOps root;
    // this task still owns its old Linux mm while the NT replacement is private.
    // Keep the non-sleeping prefault/write interval on the new root and prevent
    // a scheduler switch until the old root is restored.
    let previous_root = hal_x86_64::read_cr3() & !(hal::PAGE_SIZE_BYTES - 1);
    let preempt = sched::preempt::PreemptGuard::new();
    // SAFETY: `as_` is the unpublished replacement with a shared kernel half;
    // preemption is disabled for the explicit-root page population interval.
    unsafe { <hal_x86_64::mmu_ops::X86Mmu as MmuOps>::activate(as_.root_pa()); }
    let prefault = pmm::user_as::prefault_user_range(as_, plan.start(), plan.write_len()).is_ok();
    let layout = if prefault {
        elf_load::stack::build_user_stack_in(as_, plan, &argv, &envp, &image, &random16,
            b"/usr/local/bin/windows-runtime", 0, 0, 0, elf_load::stack::AuxCreds::default(), 0)
    } else { None };
    // SAFETY: `previous_root` is the running task's still-owned Linux mm root;
    // it is restored before the preemption guard can schedule another task.
    unsafe { <hal_x86_64::mmu_ops::X86Mmu as MmuOps>::activate(previous_root); }
    drop(preempt);
    if !prefault {
        klog::write_raw(b"[WINDOWS-PE-BOOTSTRAP-FAIL] stage=stack-prefault\n");
        return Err(enoexec);
    }
    let layout = match layout {
        Some(layout) => layout,
        None => {
            klog::write_raw(b"[WINDOWS-PE-BOOTSTRAP-FAIL] stage=stack-build\n");
            return Err(enoexec);
        }
    };
    Ok((image.user_ip(), layout.sp))
}

#[cfg(target_arch = "x86_64")]
fn log_bootstrap_failure(stage: &'static [u8], error: elf_load::LoadError) {
    klog::write_raw(b"[WINDOWS-PE-BOOTSTRAP-FAIL] stage=");
    klog::write_raw(stage);
    klog::write_raw(b" error=");
    klog::write_raw(match error {
        elf_load::LoadError::Enoexec => b"enoexec",
        elf_load::LoadError::Einval => b"einval",
        elf_load::LoadError::Enomem => b"enomem",
    });
    klog::write_raw(b"\n");
}

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
fn nomem(message: &'static [u8]) -> i64 {
    klog::write_raw(message);
    -(syscall::errno::Errno::Enomem.as_i32() as i64)
}
