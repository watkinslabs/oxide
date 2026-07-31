// `PTRACE_GET_SYSCALL_INFO` / `PTRACE_SET_SYSCALL_INFO` — `struct
// ptrace_syscall_info` layout, the op classification, and the two validation
// ladders. Pure bytes-in / bytes-out so every offset and errno is reachable
// from `cargo test`; the live register plumbing is the kernel-only sibling.
//
// Layout (`include/uapi/linux/ptrace.h`, 64-bit):
//   op u8 @0, reserved u8 @1, flags u16 @2, arch u32 @4,
//   instruction_pointer u64 @8, stack_pointer u64 @16, union @24
//     entry   { nr u64 @24, args[6] u64 @32 }              end 80
//     exit    { rval s64 @24, is_error u8 @32 }            end 33
//     seccomp { nr u64 @24, args[6] @32, ret_data u32 @80 } end 84
// `sizeof` is 88 (the union is 64 bytes, 8-aligned).

use syscall::errno::Errno;
use crate::s101_ptrace_uapi as uapi;
use crate::s101_ptrace_event as event;

/// `PTRACE_SYSCALL_INFO_*` op codes.
pub const OP_NONE:    u8 = 0;
pub const OP_ENTRY:   u8 = 1;
pub const OP_EXIT:    u8 = 2;
pub const OP_SECCOMP: u8 = 3;

/// Syscall arguments carried by the entry/seccomp arms.
pub const NARGS: usize = 6;

pub const OFF_OP:       usize = 0;
pub const OFF_RESERVED: usize = 1;
pub const OFF_FLAGS:    usize = 2;
pub const OFF_ARCH:     usize = 4;
pub const OFF_IP:       usize = 8;
pub const OFF_SP:       usize = 16;
pub const OFF_UNION:    usize = 24;
pub const OFF_ENTRY_NR:       usize = 24;
pub const OFF_ENTRY_ARGS:     usize = 32;
pub const OFF_EXIT_RVAL:      usize = 24;
pub const OFF_EXIT_IS_ERROR:  usize = 32;
pub const OFF_SECCOMP_RET_DATA: usize = 80;

/// `sizeof(struct ptrace_syscall_info)`.
pub const SIZEOF: usize = 88;
/// `offsetofend` values — the byte count `PTRACE_GET_SYSCALL_INFO` reports as
/// its return value for each op, which is how a tracer learns how much of the
/// record the kernel actually filled in.
pub const END_NONE:    usize = OFF_UNION;
pub const END_ENTRY:   usize = OFF_ENTRY_ARGS + NARGS * 8;
pub const END_EXIT:    usize = OFF_EXIT_IS_ERROR + 1;
pub const END_SECCOMP: usize = OFF_SECCOMP_RET_DATA + 4;

/// The register facts a syscall-stop record is built from. `rval` is the
/// value the tracee's ABI return register holds at the stop.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct Regs {
    pub nr:   u64,
    pub args: [u64; NARGS],
    pub ip:   u64,
    pub sp:   u64,
    pub rval: i64,
}

/// Linux `ptrace_get_syscall_info_op`: the kind of syscall stop the tracee is
/// in, read off the `si_code` its `last_siginfo` carries plus the
/// `ptrace_message` the stop recorded. Anything that is not a syscall or
/// seccomp stop is `PTRACE_SYSCALL_INFO_NONE` — including a signal-delivery
/// stop, whose record therefore carries only the header.
/// # C: O(1)
pub fn op_of(si_code: Option<i32>, eventmsg: u64) -> u8 {
    let code = match si_code { Some(c) => c, None => return OP_NONE };
    if code == uapi::syscall_stop_code() {
        return match eventmsg {
            event::EVENTMSG_SYSCALL_ENTRY => OP_ENTRY,
            event::EVENTMSG_SYSCALL_EXIT  => OP_EXIT,
            _ => OP_NONE,
        };
    }
    if code == uapi::event_stop_code(uapi::EVENT_SECCOMP) { return OP_SECCOMP; }
    OP_NONE
}

/// `syscall_get_error(child, regs)` — Linux reports an error return as the
/// negative errno and a success return as the value itself, with `is_error`
/// distinguishing them. The error window is the same `-MAX_ERRNO..=-1` the
/// syscall ABI uses.
/// # C: O(1)
pub fn is_error(rval: i64) -> bool { (-(MAX_ERRNO as i64)..0).contains(&rval) }

/// Linux `MAX_ERRNO` — the largest value a syscall may return as `-errno`.
pub const MAX_ERRNO: u64 = 4095;

/// Serialise the record. Returns `(bytes, actual_size)`: `actual_size` is
/// what `PTRACE_GET_SYSCALL_INFO` returns to the tracer, and the caller
/// copies out `min(actual_size, user_size)` — a short user buffer truncates
/// the copy but NOT the reported size, which is how a tracer detects that it
/// needs a bigger buffer.
/// # C: O(1)
pub fn encode(op: u8, arch: u32, r: &Regs, ret_data: u32) -> ([u8; SIZEOF], usize) {
    let mut b = [0u8; SIZEOF];
    b[OFF_OP] = op;
    b[OFF_ARCH..OFF_ARCH + 4].copy_from_slice(&arch.to_ne_bytes());
    b[OFF_IP..OFF_IP + 8].copy_from_slice(&r.ip.to_ne_bytes());
    b[OFF_SP..OFF_SP + 8].copy_from_slice(&r.sp.to_ne_bytes());
    let end = match op {
        OP_ENTRY | OP_SECCOMP => {
            b[OFF_ENTRY_NR..OFF_ENTRY_NR + 8].copy_from_slice(&r.nr.to_ne_bytes());
            for i in 0..NARGS {
                let o = OFF_ENTRY_ARGS + i * 8;
                b[o..o + 8].copy_from_slice(&r.args[i].to_ne_bytes());
            }
            if op == OP_SECCOMP {
                b[OFF_SECCOMP_RET_DATA..OFF_SECCOMP_RET_DATA + 4]
                    .copy_from_slice(&ret_data.to_ne_bytes());
                END_SECCOMP
            } else { END_ENTRY }
        }
        OP_EXIT => {
            let err = is_error(r.rval);
            b[OFF_EXIT_RVAL..OFF_EXIT_RVAL + 8].copy_from_slice(&r.rval.to_ne_bytes());
            b[OFF_EXIT_IS_ERROR] = u8::from(err);
            END_EXIT
        }
        _ => END_NONE,
    };
    (b, end)
}

/// What a `PTRACE_SET_SYSCALL_INFO` request asks the kernel to install.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SetRequest {
    /// Rewrite the syscall number and its six arguments. `nr == -1` cancels
    /// the syscall; Linux then leaves the argument registers alone, because on
    /// some ABIs the first argument register doubles as the return register.
    Entry { nr: i64, args: [u64; NARGS], set_args: bool },
    /// Rewrite the return value. `is_error` selects which of Linux's two
    /// `syscall_set_return_value` forms applies.
    Exit { rval: i64, is_error: bool },
}

/// Linux `ptrace_set_syscall_info`, in its exact order:
///   1. `user_size < sizeof(info)` -> EINVAL (a short record is refused
///      outright, unlike the GET direction which truncates).
///   2. a non-zero `flags` or `reserved` -> EINVAL (reserved for future use).
///   3. the record's `op` must equal the stop the tracee is actually in ->
///      EINVAL; changing the KIND of a syscall stop is not supported.
///   4. per-op range checks -> ERANGE.
/// `NONE` and every unknown op are EINVAL.
/// # C: O(1)
pub fn decode_set(cur_op: u8, user_size: usize, rec: &[u8]) -> Result<SetRequest, Errno> {
    if user_size < SIZEOF { return Err(Errno::Einval); }
    if rec.len() < SIZEOF { return Err(Errno::Efault); }
    if rec[OFF_RESERVED] != 0 { return Err(Errno::Einval); }
    if u16::from_ne_bytes([rec[OFF_FLAGS], rec[OFF_FLAGS + 1]]) != 0 { return Err(Errno::Einval); }
    if rec[OFF_OP] != cur_op { return Err(Errno::Einval); }
    match cur_op {
        OP_ENTRY | OP_SECCOMP => {
            // `int nr = info->entry.nr; if (nr != info->entry.nr)` — the
            // number must survive a round trip through `int`.
            let raw = u64::from_ne_bytes(rec_u64(rec, OFF_ENTRY_NR));
            let nr = raw as i32 as i64;
            if nr as u64 != raw { return Err(Errno::Erange); }
            let mut args = [0u64; NARGS];
            for i in 0..NARGS {
                args[i] = u64::from_ne_bytes(rec_u64(rec, OFF_ENTRY_ARGS + i * 8));
            }
            // `info->seccomp.ret_data` is accepted and ignored, as Linux does.
            Ok(SetRequest::Entry { nr, args, set_args: nr != -1 })
        }
        OP_EXIT => {
            let rval = i64::from_ne_bytes(rec_u64(rec, OFF_EXIT_RVAL));
            Ok(SetRequest::Exit { rval, is_error: rec[OFF_EXIT_IS_ERROR] != 0 })
        }
        _ => Err(Errno::Einval),
    }
}

fn rec_u64(rec: &[u8], off: usize) -> [u8; 8] {
    let mut b = [0u8; 8];
    b.copy_from_slice(&rec[off..off + 8]);
    b
}

/// `syscall_set_return_value(child, regs, error, val)` — Linux passes the
/// value in the `error` slot when `is_error`, and in the `val` slot
/// otherwise, which on both supported ABIs means the return register simply
/// takes `rval` either way. Expressed as one function so the two arms cannot
/// drift apart.
/// # C: O(1)
pub fn exit_return_register(rval: i64, _is_error: bool) -> i64 { rval }

/// `struct ptrace_sud_config { u64 mode; u64 selector; u64 offset; u64 len; }`
/// — the record `PTRACE_{GET,SET}_SYSCALL_USER_DISPATCH_CONFIG` exchanges.
pub const SUD_OFF_MODE:     usize = 0;
pub const SUD_OFF_SELECTOR: usize = 8;
pub const SUD_OFF_OFFSET:   usize = 16;
pub const SUD_OFF_LEN:      usize = 24;
pub const SUD_SIZEOF:       usize = 32;

/// A syscall-user-dispatch registration as the ptrace record carries it.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct SudConfig { pub mode: u64, pub selector: u64, pub offset: u64, pub len: u64 }

/// Both directions take the record size in `addr` and require it to be
/// EXACT: `if (size != sizeof(cfg)) return -EINVAL;`. Unlike
/// `PTRACE_GET_SYSCALL_INFO` there is no truncation and no short-buffer
/// report — the record is versioned by its size alone.
/// # C: O(1)
pub fn sud_size_ok(size: u64) -> Result<(), Errno> {
    if size as usize != SUD_SIZEOF { return Err(Errno::Einval); }
    Ok(())
}

/// # C: O(1)
pub fn sud_encode(c: &SudConfig) -> [u8; SUD_SIZEOF] {
    let mut b = [0u8; SUD_SIZEOF];
    b[SUD_OFF_MODE..SUD_OFF_MODE + 8].copy_from_slice(&c.mode.to_ne_bytes());
    b[SUD_OFF_SELECTOR..SUD_OFF_SELECTOR + 8].copy_from_slice(&c.selector.to_ne_bytes());
    b[SUD_OFF_OFFSET..SUD_OFF_OFFSET + 8].copy_from_slice(&c.offset.to_ne_bytes());
    b[SUD_OFF_LEN..SUD_OFF_LEN + 8].copy_from_slice(&c.len.to_ne_bytes());
    b
}

/// # C: O(1)
pub fn sud_decode(b: &[u8; SUD_SIZEOF]) -> SudConfig {
    SudConfig {
        mode:     u64::from_ne_bytes(rec_u64(b, SUD_OFF_MODE)),
        selector: u64::from_ne_bytes(rec_u64(b, SUD_OFF_SELECTOR)),
        offset:   u64::from_ne_bytes(rec_u64(b, SUD_OFF_OFFSET)),
        len:      u64::from_ne_bytes(rec_u64(b, SUD_OFF_LEN)),
    }
}

/// `PR_SYS_DISPATCH_ON` / `_OFF` — the GET direction reports only whether
/// dispatch is armed, never which of the two ON modes armed it (the stored
/// range is already normalised and the original mode is not kept).
pub const PR_SYS_DISPATCH_OFF: u64 = 0;
pub const PR_SYS_DISPATCH_ON:  u64 = 1;

#[cfg(test)]
#[path = "sysinfo/tests.rs"] mod tests;
