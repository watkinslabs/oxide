// ptrace(2) ABI constants — `include/uapi/linux/ptrace.h`,
// `arch/x86/include/uapi/asm/ptrace-abi.h`, `include/uapi/linux/elf.h`.
// Numbers only; no policy (`52` UAPI-is-not-policy rule).

/// Classic request numbers (identical on x86_64 and arm64).
pub const TRACEME:    u64 = 0;
pub const PEEKTEXT:   u64 = 1;
pub const PEEKDATA:   u64 = 2;
pub const PEEKUSER:   u64 = 3;
pub const POKETEXT:   u64 = 4;
pub const POKEDATA:   u64 = 5;
pub const POKEUSER:   u64 = 6;
pub const CONT:       u64 = 7;
pub const KILL:       u64 = 8;
pub const SINGLESTEP: u64 = 9;
/// x86-only (`arch_ptrace`); arm64 has no GETREGS/SETREGS/GETFPREGS/SETFPREGS
/// and falls through to `ptrace_request`, whose default arm returns EIO.
pub const GETREGS:    u64 = 12;
pub const SETREGS:    u64 = 13;
pub const GETFPREGS:  u64 = 14;
pub const SETFPREGS:  u64 = 15;
pub const ATTACH:     u64 = 16;
pub const DETACH:     u64 = 17;
pub const SYSCALL:    u64 = 24;

/// `PTRACE_SETOPTIONS`..`PTRACE_SETSIGMASK` extended block.
pub const SETOPTIONS:  u64 = 0x4200;
pub const GETEVENTMSG: u64 = 0x4201;
pub const GETSIGINFO:  u64 = 0x4202;
pub const SETSIGINFO:  u64 = 0x4203;
pub const GETREGSET:   u64 = 0x4204;
pub const SETREGSET:   u64 = 0x4205;
pub const SEIZE:       u64 = 0x4206;
pub const INTERRUPT:   u64 = 0x4207;
pub const LISTEN:      u64 = 0x4208;
pub const PEEKSIGINFO: u64 = 0x4209;
pub const GETSIGMASK:  u64 = 0x420a;
pub const SETSIGMASK:  u64 = 0x420b;

/// `PTRACE_O_*` option bits.
pub const O_TRACESYSGOOD:    u32 = 1;
pub const O_TRACEFORK:       u32 = 1 << EVENT_FORK;
pub const O_TRACEVFORK:      u32 = 1 << EVENT_VFORK;
pub const O_TRACECLONE:      u32 = 1 << EVENT_CLONE;
pub const O_TRACEEXEC:       u32 = 1 << EVENT_EXEC;
pub const O_TRACEVFORKDONE:  u32 = 1 << EVENT_VFORK_DONE;
pub const O_TRACEEXIT:       u32 = 1 << EVENT_EXIT;
pub const O_TRACESECCOMP:    u32 = 1 << EVENT_SECCOMP;
pub const O_EXITKILL:        u32 = 1 << 20;
pub const O_SUSPEND_SECCOMP: u32 = 1 << 21;
/// Linux `PTRACE_O_MASK` = `0x000000ff | EXITKILL | SUSPEND_SECCOMP`.
pub const O_MASK: u32 = 0x0000_00ff | O_EXITKILL | O_SUSPEND_SECCOMP;

/// `PTRACE_EVENT_*` codes reported in the high byte of a wait status.
pub const EVENT_FORK:       u32 = 1;
pub const EVENT_VFORK:      u32 = 2;
pub const EVENT_CLONE:      u32 = 3;
pub const EVENT_EXEC:       u32 = 4;
pub const EVENT_VFORK_DONE: u32 = 5;
pub const EVENT_EXIT:       u32 = 6;
pub const EVENT_SECCOMP:    u32 = 7;
pub const EVENT_STOP:       u32 = 128;

/// `NT_*` regset note types (`include/uapi/linux/elf.h`). `PTRACE_GETREGSET`
/// takes one of these in `addr`.
pub const NT_PRSTATUS: u64 = 1;
pub const NT_PRFPREG:  u64 = 2;
pub const NT_X86_XSTATE: u64 = 0x202;
pub const NT_ARM_SYSTEM_CALL: u64 = 0x404;

/// Highest signal number `valid_signal()` accepts (`_NSIG`).
pub const NSIG: u64 = 64;

/// `sizeof(struct user_regs_struct)` on x86_64: 27 unsigned longs.
pub const X86_USER_REGS_N: usize = 27;
/// `sizeof(struct user)` on x86_64 — the PEEKUSER/POKEUSER address ceiling.
/// regs(216) + u_fpvalid+pad0(8) + i387(512) + 5 ulongs(40) + signal/reserved/pad1(16)
/// + u_ar0(8) + u_fpstate(8) + magic(8) + u_comm[32] + u_debugreg[8](64)
/// + error_code(8) + fault_address(8) = 920.
pub const X86_SIZEOF_USER: u64 = 920;
/// Byte offset of `u_debugreg[0]` inside `struct user` on x86_64.
pub const X86_USER_DEBUGREG_OFF: u64 = 848;

/// `sizeof(struct user_pt_regs) / 8` on arm64: `regs[31] + sp + pc + pstate`.
pub const ARM64_USER_PT_REGS_N: usize = 34;

/// FP regset payload sizes: `struct user_i387_struct` (x86_64 FXSAVE image)
/// and `struct user_fpsimd_state` (arm64 NEON image).
pub const X86_USER_I387_BYTES: usize = 512;
pub const ARM64_USER_FPSIMD_BYTES: usize = 528;
