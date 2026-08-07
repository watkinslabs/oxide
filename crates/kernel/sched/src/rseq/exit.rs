// rseq exit-to-user work: id writeback (`rseq_set_ids_get_csaddr`) and the
// critical-section abort (`rseq_update_user_cs`), per
// `include/linux/rseq_entry.h`.

use core::sync::atomic::Ordering;
use syscall::rseq as abi;

use super::uaccess as ua;

/// `Task::rseq_ids` sentinel meaning "nothing published yet" — forces the
/// next exit-to-user to write the area even if the cpu id happens to match.
pub const IDS_UNSET: u64 = u64::MAX;

/// Pack the published (cpu_id, mm_cid) pair for the per-task cache.
/// `node_id` is not cached: oxide reports a single NUMA node. # C: O(1)
fn pack_ids(cpu_id: u32, mm_cid: u32) -> u64 { (cpu_id as u64) | ((mm_cid as u64) << 32) }

/// The logical CPU this thread is running on, from the arch HAL. # C: O(1)
fn current_cpu_id() -> u32 {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    { use hal::CpuOps; hal_x86_64::X86CpuOps::current_cpu() }
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    { use hal::CpuOps; hal_aarch64::ArmCpuOps::current_cpu() }
    #[cfg(not(target_os = "oxide-kernel"))]
    { 0 }
}

/// Linux `rseq_set_ids_get_csaddr`'s write half. Republishes `cpu_id_start`,
/// `cpu_id`, `node_id` and `mm_cid` when they moved since the last exit.
///
/// `mm_cid` is the CPU id. Linux's contract for that field is "unique among
/// the threads of this mm that are concurrently running, and below the CPU
/// count" — the CPU id satisfies both by construction, because two threads
/// of one mm can never occupy the same CPU at the same instant. Linux
/// additionally keeps the value compact; that is an allocator quality goal,
/// not part of the ABI guarantee user space may rely on.
///
/// Returns false when the area faulted, which means the registration is no
/// longer usable. # C: O(1)
fn update_ids(cur: &crate::Task, ptr: u64) -> bool {
    let cpu = current_cpu_id();
    let packed = pack_ids(cpu, cpu);
    if cur.rseq_ids.load(Ordering::Relaxed) == packed { return true; }
    // No NUMA topology: every CPU reports node 0, matching `cpu_to_node` on a
    // kernel built without CONFIG_NUMA.
    if ua::put_ids(ptr, cpu, 0, cpu).is_err() { return false; }
    cur.rseq_ids.store(packed, Ordering::Relaxed);
    true
}

/// Republish the rseq ids on the syscall-return path.
///
/// No critical-section work here: an rseq critical section may not contain a
/// syscall (`Documentation/userspace-api/rseq.rst`), so the user PC on this
/// path is by construction outside every `rseq_cs` range. The abort lives on
/// the preemption path, `rseq_preempt_return`.
/// # C: O(1)
/// # Ctx: syscall-return tail
pub fn rseq_writeback() {
    let cur = match crate::live::current() { Some(c) => c, None => return };
    let ptr = cur.rseq_ptr.load(Ordering::Acquire);
    if ptr == 0 { return; }
    if !update_ids(cur, ptr) { registration_died(cur); }
}

/// Linux `rseq_exit_to_user_mode_restart` → `rseq_update_user_cs`: the real
/// restartable-sequence abort.
///
/// Called from the IRQ-exit tail on BOTH arches after `schedule()` actually
/// switched away and back, with `ip` aliasing the interrupted frame's saved
/// user PC (x86 iretq RIP, arm ELR_EL1). If the thread was inside a declared
/// critical section when it lost the CPU, the section is invalidated and the
/// PC is rewritten to `abort_ip`, so the commit never runs against per-cpu
/// state another thread mutated in the gap. Without this the whole rseq
/// contract is a lie: user space takes the fast path believing preemption
/// aborts it.
///
/// `abort_ip`'s preceding four bytes must equal the registered signature.
/// That check is what stops an attacker who can write `rseq_cs` from
/// redirecting the abort at an arbitrary ROP gadget; a mismatch is fatal.
/// # C: O(1)
/// # Ctx: IRQ-exit, returning to user
pub fn rseq_preempt_return(ip: &mut u64) {
    let cur = match crate::live::current() { Some(c) => c, None => return };
    let ptr = cur.rseq_ptr.load(Ordering::Acquire);
    if ptr == 0 { return; }
    if !update_ids(cur, ptr) { registration_died(cur); }
    let csaddr = match ua::get_u64(ptr + abi::RSEQ_OFF_RSEQ_CS) {
        Ok(v) => v,
        Err(_) => registration_died(cur),
    };
    if csaddr == 0 { return; }
    if !abi::cs_addr_usable(csaddr, hal::USER_VA_END) { registration_died(cur); }
    let start_ip = ua::get_u64(csaddr + abi::RSEQ_CS_OFF_START_IP);
    let offset   = ua::get_u64(csaddr + abi::RSEQ_CS_OFF_POST_COMMIT_OFFSET);
    let abort_ip = ua::get_u64(csaddr + abi::RSEQ_CS_OFF_ABORT_IP);
    let (start_ip, offset, abort_ip) = match (start_ip, offset, abort_ip) {
        (Ok(s), Ok(o), Ok(a)) => (s, o, a),
        _ => registration_died(cur),
    };
    // Linux reads the signature word unconditionally inside the uaccess
    // region and only compares it on the in-section path; a read failure
    // there is an EFAULT exit, so an unreadable word is fatal either way.
    let usig = if abort_ip >= abi::RSEQ_SIG_BYTES && abort_ip < hal::USER_VA_END {
        ua::get_u32(abort_ip - abi::RSEQ_SIG_BYTES).unwrap_or(!cur.rseq_sig.load(Ordering::Acquire))
    } else { 0 };
    let sig = cur.rseq_sig.load(Ordering::Acquire);
    match abi::cs_outcome(*ip, start_ip, offset, abort_ip, hal::USER_VA_END, sig, usig) {
        abi::CsOutcome::Fixup(target) => {
            if ua::put_u64(ptr + abi::RSEQ_OFF_RSEQ_CS, 0).is_err() { registration_died(cur); }
            *ip = target;
        }
        abi::CsOutcome::Clear => {
            if ua::put_u64(ptr + abi::RSEQ_OFF_RSEQ_CS, 0).is_err() { registration_died(cur); }
        }
        abi::CsOutcome::Fatal => registration_died(cur),
    }
}

/// Linux's fatal rseq exit: the registration is unusable, so the thread dies
/// with SIGSEGV (`force_sigsegv` → `SIG_DFL` → group-fatal). Reached only
/// when user space handed the kernel an unusable area or descriptor.
/// # C: task-exit teardown
pub(crate) fn registration_died(cur: &crate::Task) -> ! {
    ua::mark_registration_failed(cur);
    cur.rseq_ptr.store(0, Ordering::Release);
    cur.rseq_len.store(0, Ordering::Release);
    cur.rseq_sig.store(0, Ordering::Release);
    crate::live::terminate_current_with_signal(crate::signum::Signum::Sigsegv.as_u8())
}
