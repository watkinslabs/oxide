// Building the helper process.
//
// Order matters and mirrors what a fork-then-exec does: the process exists
// before it is customised, is customised before its image is loaded, and is
// made runnable only once every field it could observe is final. Publishing
// earlier is the window that would let a helper reach user mode with no
// descriptor table and fail its first write.

use alloc::sync::Arc;
use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::info::{HelperCtx, SubprocessInfo};
use crate::uapi::UMH_UMASK;

use super::arch;

/// Stage marker for the boot self-test, so a wedge names the statement it
/// happened in rather than the whole helper start.
macro_rules! stage {
    ($m:literal) => { #[cfg(feature = "debug-umh")] { klog::write_raw(b"[UMH-STAGE] "); klog::write_raw($m); klog::write_raw(b"\n"); } };
}

/// Stack reservation for a helper. Helpers are small programs; this is the same
/// reservation the boot loader gives the initial process.
const HELPER_STACK_BYTES: u64 = 0x10000;

/// Build and start the helper described by `info`.
///
/// Returns the started process on success. On failure the negated errno is the
/// exec result a waiting caller reports — a missing program is `-ENOENT`, which
/// is the case that matters most because it is the usual state of a system with
/// no helper installed.
/// # C: O(phdrs) + O(image size)
pub fn start(info: &mut SubprocessInfo) -> Result<Arc<sched::Task>, i32> {
    let mm = new_address_space()?;
    let tid = sched::live::next_tid();
    // SAFETY: worker-thread process context with the allocator and HAL up; the task stays unpublished until `wake` below, so this thread is its sole writer throughout.
    let task = unsafe {
        sched::live::new_user_task_unpublished(tid, 0, 0, "umh", Arc::clone(&mm))
    }.map_err(|_| -(Errno::Enomem.as_i32()))?;
    // A helper runs in the initial PID namespace and draws its number from it,
    // through its own PID identity, so the number is returned when the helper
    // is released.
    task.alloc_pid_mappings(&[], true).map_err(|_| -(Errno::Eagain.as_i32()))?;
    let vpid = task.vtgid.load(core::sync::atomic::Ordering::Acquire);
    task.set_pgid(vpid);
    task.set_sid(vpid);

    stage!(b"task-built");
    let fdt = Arc::new(vfs::FdTable::new());
    // SAFETY: the task is unpublished and has never been scheduled, so no other holder of its descriptor slot exists.
    unsafe { task.replace_fd_table(Some(Arc::clone(&fdt))); }
    adopt_initial_namespace(&task);
    // A helper inherits the initial kernel filesystem context, whose mask is 0;
    // without this reset every file it creates would be world-writable.
    task.fs_context().swap_umask(UMH_UMASK);
    task.exit_signal.store(sched::Signum::Sigchld as u8, core::sync::atomic::Ordering::Release);
    if let Some(worker) = sched::live::current() {
        task.parent_tid.store(worker.tid, core::sync::atomic::Ordering::Release);
    }

    // The caller's customisation runs against a process that exists but has no
    // image yet — the window a descriptor install or a credential change needs.
    let ctx = HelperCtx { task: Arc::clone(&task), fdt };
    let rc = info.run_init(&ctx);
    if rc != 0 { return Err(rc); }

    stage!(b"init-done");
    let program = super::image::read_program(info.path_bytes())?;
    stage!(b"program-read");
    let entry = load_image(&mm, &program, info, &task)?;
    // SAFETY: the task is still unpublished, so this is the sole writer of its arch context; entry/sp were produced by the loader against this task's own address space.
    unsafe { sched::live::arm_user_entry(&task, entry.0, entry.1); }
    stage!(b"entry-armed");
    sched::live::publish_new_task(&task);
    stage!(b"published");
    sched::live::wake_new_task(&task);
    Ok(task)
}

/// A helper resolves paths against the initial namespace's root, not against
/// whichever process asked for it — a chrooted caller must not be able to
/// redirect a kernel helper. # C: O(1)
fn adopt_initial_namespace(task: &sched::Task) {
    let ns = vfs::mount::current_ns();
    if let Some(root) = vfs::mount::root_path_for_ns(ns) {
        let fs = task.fs_context();
        fs.set_root(alloc::string::String::from("/"), root.clone());
        fs.set_cwd(alloc::string::String::from("/"), root);
    }
}

fn new_address_space() -> Result<Arc<vmm::AddressSpace>, i32> {
    let root = arch::new_user_root().ok_or(-(Errno::Enomem.as_i32()))?;
    let mm = vmm::AddressSpace::new(root).map_err(|_| -(Errno::Enomem.as_i32()))?;
    pmm::user_as::install_teardown(&mm);
    Ok(mm)
}

/// Place the image and its initial stack, returning `(entry, stack pointer)`.
///
/// The loader writes through the NEW address space's user addresses, so it runs
/// with that address space installed. This is legal only because the caller is
/// a worker thread with no address space of its own; the space is pinned as
/// this processor's lazily-resident one afterwards so it cannot be freed while
/// still held in the page-table root register.
fn load_image(mm: &Arc<vmm::AddressSpace>, program: &[u8], info: &SubprocessInfo,
              task: &sched::Task) -> Result<(u64, u64), i32> {
    use hal::UserVirtAddr;
    use vmm::{VmaBacking, VmaProt};

    let rnd = aslr::ExecRnd::draw(false);
    let stack_top = rnd.stack_top();
    let stack_va = stack_top - HELPER_STACK_BYTES;
    let hint = UserVirtAddr::new(stack_va).ok_or(-(Errno::Enomem.as_i32()))?;

    // Borrow the helper's space for the load. Switching only the page-table
    // root would not survive the loader sleeping on a disk read: the scheduler
    // restores the root of whatever ran next and would not restore this one,
    // leaving the loader writing user addresses through another process's page
    // tables. Borrowing makes the restore correct, and pins the space so the
    // helper cannot free it while this thread is still resident on it.
    // SAFETY: the helper thread owns no address space of its own, and this root carries the shared kernel half; every exit below releases the borrow.
    unsafe { sched::live::kthread_use_mm(mm); }

    stage!(b"activated");
    if mm.mmap(Some(hint), HELPER_STACK_BYTES as usize,
               VmaProt::READ | VmaProt::WRITE,
               vmm::EXEC_STACK_VMA_FLAGS, VmaBacking::Anonymous, true).is_err() {
        release_borrow();
        return Err(-(Errno::Enomem.as_i32()));
    }
    mm.set_mmap_base(rnd.mmap_base(HELPER_STACK_BYTES));

    stage!(b"stack-mapped");
    let img = match elf_load::load_static_blob(program, mm, &rnd) {
        Ok(i) => i,
        Err(_) => { release_borrow(); return Err(-(Errno::Enoexec.as_i32())); }
    };

    // The stack is written from kernel context through user addresses, so it is
    // mapped up front rather than demand-faulted: the fault handler resolves
    // against the RUNNING task's address space, and the running task here is
    // the worker, not the helper.
    stage!(b"image-loaded");
    pmm::user_as::prefault_stack(mm, stack_top, HELPER_STACK_BYTES);

    stage!(b"stack-prefaulted");
    let mut random16 = [0u8; 16];
    crng::fill(&mut random16);
    let argv = flatten(&info.argv);
    let envp = flatten(&info.envp);
    let argv_slices: Vec<&[u8]> = argv.iter().map(|v| v.as_slice()).collect();
    let envp_slices: Vec<&[u8]> = envp.iter().map(|v| v.as_slice()).collect();
    // SAFETY: the helper's address space is the installed one and its stack is mapped above, so every write lands in it.
    let layout = unsafe {
        elf_load::stack::build_user_stack(
            stack_top, HELPER_STACK_BYTES, &argv_slices, &envp_slices, &img,
            &random16, info.path_bytes(), 0, arch::cpu_hwcap(),
            // A helper runs with the full kernel credential set and gains no
            // privilege by being exec'd, so the secure-execution flag is clear.
            elf_load::stack::AuxCreds::default(),
            arch::cpu_min_sigstksz(), &rnd)
    };
    let Some(layout) = layout else { release_borrow(); return Err(-(Errno::Enomem.as_i32())); };
    stage!(b"stack-built");
    elf_load::commit_mm_layout(mm, &img, &layout);
    name_after_program(task, info.path_bytes());
    record_identity(task, mm, info);
    release_borrow();
    Ok((img.user_ip(), layout.sp))
}

/// Give the borrowed space back. The root stays installed until the next real
/// activation, and stays pinned until then, so nothing frees it under us.
fn release_borrow() {
    // SAFETY: pairs with the `kthread_use_mm` above on this same thread.
    unsafe { sched::live::kthread_unuse_mm(); }
}

/// argv/envp default to naming the program itself when a caller supplied
/// neither, so a helper always sees a valid `argv[0]`.
fn flatten(v: &[Vec<u8>]) -> Vec<Vec<u8>> { v.to_vec() }

fn name_after_program(task: &sched::Task, path: &[u8]) {
    let base = path.rsplit(|&b| b == b'/').next().unwrap_or(path);
    if base.is_empty() { return; }
    task.set_comm_raw(base);
}

fn record_identity(task: &sched::Task, mm: &Arc<vmm::AddressSpace>, info: &SubprocessInfo) {
    if let Ok(s) = core::str::from_utf8(info.path_bytes()) {
        let owned = alloc::string::String::from(s);
        task.set_exe_path(Some(owned.clone()));
        mm.set_exe_path(owned);
    }
    let argv: Vec<&[u8]> = info.argv.iter().map(|v| v.as_slice()).collect();
    let envp: Vec<&[u8]> = info.envp.iter().map(|v| v.as_slice()).collect();
    task.set_cmdline(Some(sched::argv_to_cmdline(&argv)));
    task.set_environ(Some(sched::argv_to_cmdline(&envp)));
}
