//! Loaded-program runners and their extra memory domains.

use super::execute::{Helper, HelperState, run_inner};
use super::memory::{Context, RunMemory};

/// Run a loaded program with relocated maps and separate context/packet data.
/// # C: O(insn count × step budget)
pub fn run_program_with_state(
    prog: &crate::bpf::BpfProgInode,
    context: &[u8],
    packet: &[u8],
    helpers: &[Helper],
    helper_state: &mut HelperState,
) -> Option<i64> {
    prog.stats.run(|| {
        let maps = prog.maps.lock();
        let mut memory = RunMemory::new(Context::ReadOnly(context), packet, &maps);
        memory.attach_prog(prog);
        run_inner(&prog.insns, helpers, helper_state, memory)
    })
}

/// Run with one verifier-approved typed kernel-object view.
/// # C: O(insn count × step budget)
pub(crate) fn run_program_with_kernel_state(
    prog: &crate::bpf::BpfProgInode,
    context: &[u8],
    kernel_base: u64,
    kernel: &[u8],
    helper_state: &mut HelperState,
) -> Option<i64> {
    prog.stats.run(|| {
        let maps = prog.maps.lock();
        let mut memory = RunMemory::new(Context::ReadOnly(context), &[], &maps);
        memory.attach_kernel(kernel_base, kernel);
        memory.attach_prog(prog);
        run_inner(&prog.insns, &[], helper_state, memory)
    })
}

/// Mutable-context variant for `BPF_PROG_TYPE_CGROUP_SOCK_ADDR`.
/// # C: O(insn count × step budget)
pub fn run_program_mut_with_state(
    prog: &crate::bpf::BpfProgInode,
    context: &mut [u8],
    helpers: &[Helper],
    helper_state: &mut HelperState,
) -> Option<i64> {
    prog.stats.run(|| {
        let maps = prog.maps.lock();
        let mut memory = RunMemory::new(Context::ReadWrite(context), &[], &maps);
        memory.attach_prog(prog);
        run_inner(&prog.insns, helpers, helper_state, memory)
    })
}
