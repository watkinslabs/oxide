// Syscall argument register block — the ABI boundary type per `15§4`.
// The per-arch syscall trampoline (`15§1.1` x86_64, `15§1.2` aarch64)
// fills this from the syscall calling convention and passes it to the
// single kernel dispatcher `oxide_syscall_dispatch` (syscalls crate).

/// Args register block per `15§4`. Architecture trampoline fills this
/// from the syscall calling convention (`15§1.1` x86_64,
/// `15§1.2` aarch64).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct SyscallArgs {
    pub a0: u64, pub a1: u64, pub a2: u64,
    pub a3: u64, pub a4: u64, pub a5: u64,
}
