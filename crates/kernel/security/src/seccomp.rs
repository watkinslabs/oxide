// seccomp filter per `27` — real cBPF interpreter for v2 phase 24.
//
// Each task carries a stack of installed filters (Linux: filters
// chain in the order they were installed; the most-recent-first
// ordering applies — most restrictive action wins). On every syscall
// entry the filters run against a `seccomp_data` blob describing
// the call (nr + arch + IP + 6 args). Filter return value semantics:
//
//   SECCOMP_RET_KILL      0x00000000   terminate the task
//   SECCOMP_RET_TRAP      0x00030000   SIGSYS
//   SECCOMP_RET_ERRNO     0x00050000   substitute -errno (low 16 bits)
//   SECCOMP_RET_TRACE     0x7ff00000   ENOSYS (no ptrace tracer v1)
//   SECCOMP_RET_LOG       0x7ffc0000   allow + log
//   SECCOMP_RET_ALLOW     0x7fff0000   allow
//
// "Most restrictive action wins" means we run all filters and pick
// the lowest action number from the set of returns. v1 honors KILL,
// TRAP, ERRNO, ALLOW; LOG/TRACE/USER_NOTIF treated as ALLOW.
//
// cBPF opcode subset honored:
//   BPF_LD | BPF_W | BPF_ABS / BPF_IMM
//   BPF_JMP | BPF_JEQ / BPF_JGT / BPF_JGE / BPF_JSET / BPF_JA
//   BPF_ALU | BPF_ADD/SUB/MUL/AND/OR/XOR/LSH/RSH (BPF_K + BPF_X)
//   BPF_RET | BPF_K
//   BPF_MISC | BPF_TAX / BPF_TXA
//   BPF_ST / BPF_STX / BPF_LDX|BPF_MEM (16-slot scratch)
//
// The verifier is intentionally narrow: we cap filter length, reject
// out-of-range jumps, and bail on unknown opcodes (treated as KILL
// per Linux). No JIT — interpreter only.

#![allow(dead_code)]

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

const BPF_MAX_INSNS: usize = 4096;

const BPF_LD:    u16 = 0x00;
const BPF_LDX:   u16 = 0x01;
const BPF_ST:    u16 = 0x02;
const BPF_STX:   u16 = 0x03;
const BPF_ALU:   u16 = 0x04;
const BPF_JMP:   u16 = 0x05;
const BPF_RET:   u16 = 0x06;
const BPF_MISC:  u16 = 0x07;

const BPF_W:     u16 = 0x00;
const BPF_ABS:   u16 = 0x20;
const BPF_IND:   u16 = 0x40;
const BPF_MEM:   u16 = 0x60;
const BPF_LEN:   u16 = 0x80;
const BPF_IMM:   u16 = 0x00;

const BPF_K:     u16 = 0x00;
const BPF_X:     u16 = 0x08;

const BPF_ADD:   u16 = 0x00;
const BPF_SUB:   u16 = 0x10;
const BPF_MUL:   u16 = 0x20;
const BPF_DIV:   u16 = 0x30;
const BPF_OR:    u16 = 0x40;
const BPF_AND:   u16 = 0x50;
const BPF_LSH:   u16 = 0x60;
const BPF_RSH:   u16 = 0x70;
const BPF_NEG:   u16 = 0x80;
const BPF_MOD:   u16 = 0x90;
const BPF_XOR:   u16 = 0xA0;

const BPF_JA:    u16 = 0x00;
const BPF_JEQ:   u16 = 0x10;
const BPF_JGT:   u16 = 0x20;
const BPF_JGE:   u16 = 0x30;
const BPF_JSET:  u16 = 0x40;

const BPF_TAX:   u16 = 0x00;
const BPF_TXA:   u16 = 0x80;

pub const SECCOMP_RET_KILL:    u32 = 0x0000_0000;
pub const SECCOMP_RET_TRAP:    u32 = 0x0003_0000;
pub const SECCOMP_RET_ERRNO:   u32 = 0x0005_0000;
pub const SECCOMP_RET_TRACE:   u32 = 0x7ff0_0000;
pub const SECCOMP_RET_LOG:     u32 = 0x7ffc_0000;
pub const SECCOMP_RET_ALLOW:   u32 = 0x7fff_0000;

const SECCOMP_RET_ACTION:      u32 = 0x7fff_0000;
const SECCOMP_RET_DATA:        u32 = 0x0000_ffff;

/// `struct sock_filter` — 8 bytes. Stored 1-per-u64 in the per-task
/// filter buffer for compact representation.
#[repr(C, align(8))]
#[derive(Copy, Clone)]
struct SockFilter {
    code: u16,
    jt:   u8,
    jf:   u8,
    k:    u32,
}

/// `struct seccomp_data` — 64 bytes. Filters read this via BPF_ABS
/// loads at byte offsets:
///   0  nr (i32)
///   4  arch (u32)
///   8  instruction_pointer (u64)
///   16 args[0..6] (u64 each)
#[repr(C)]
struct SeccompData {
    nr:   i32,
    arch: u32,
    ip:   u64,
    args: [u64; 6],
}

/// Read a 32-bit big-endian-style word from `seccomp_data` at byte
/// offset `off`. cBPF treats the buffer as a network-order byte
/// array; seccomp_data is host-order, but cBPF documentation requires
/// host-order access for seccomp specifically (kernel/seccomp.c).
fn data_word(d: &SeccompData, off: u32) -> u32 {
    let off = off as usize;
    // SAFETY: SeccompData is repr(C), 64 bytes, fully initialized at the call site (we just constructed it); transmute_copy reads N bytes from a properly-aligned source which is exactly what cBPF wants for byte-offset loads.
    let bytes: [u8; 64] = unsafe { core::mem::transmute_copy(d) };
    if off + 4 > 64 { return 0; }
    u32::from_ne_bytes([bytes[off], bytes[off+1], bytes[off+2], bytes[off+3]])
}

const ARCH_X86_64: u32 = 0xc000_003e;
const ARCH_AARCH64: u32 = 0xc000_00b7;

/// Decode the i'th SockFilter from a packed-u64 program slice.
fn decode_filter(prog: &[u64], i: usize) -> SockFilter {
    let w = prog[i];
    SockFilter {
        code: (w & 0xFFFF) as u16,
        jt:   ((w >> 16) & 0xFF) as u8,
        jf:   ((w >> 24) & 0xFF) as u8,
        k:    (w >> 32) as u32,
    }
}

fn encode_filter(f: SockFilter) -> u64 {
    (f.code as u64)
        | ((f.jt as u64) << 16)
        | ((f.jf as u64) << 24)
        | ((f.k as u64)  << 32)
}

/// Run one filter program against `data`. Returns the raw return
/// value (action | data low-bits).
fn run_filter(prog: &[u64], data: &SeccompData) -> u32 {
    let mut a: u32 = 0;
    let mut x: u32 = 0;
    let mut mem: [u32; 16] = [0; 16];
    let n = prog.len();
    let mut pc: usize = 0;
    let mut steps: u32 = 0;
    let max_steps = (n as u32).saturating_mul(4).max(BPF_MAX_INSNS as u32);
    while pc < n {
        steps = steps.saturating_add(1);
        if steps > max_steps { return SECCOMP_RET_KILL; }
        let ins = decode_filter(prog, pc);
        let class = ins.code & 0x07;
        let mode  = ins.code & 0xE0;
        let src   = ins.code & 0x08;
        let op    = ins.code & 0xF0;
        match class {
            BPF_LD => match mode {
                BPF_ABS => { a = data_word(data, ins.k); pc += 1; }
                BPF_IMM => { a = ins.k; pc += 1; }
                BPF_MEM => {
                    if (ins.k as usize) >= 16 { return SECCOMP_RET_KILL; }
                    a = mem[ins.k as usize]; pc += 1;
                }
                _ => return SECCOMP_RET_KILL,
            },
            BPF_LDX => match mode {
                BPF_IMM => { x = ins.k; pc += 1; }
                BPF_MEM => {
                    if (ins.k as usize) >= 16 { return SECCOMP_RET_KILL; }
                    x = mem[ins.k as usize]; pc += 1;
                }
                _ => return SECCOMP_RET_KILL,
            },
            BPF_ST  => {
                if (ins.k as usize) >= 16 { return SECCOMP_RET_KILL; }
                mem[ins.k as usize] = a; pc += 1;
            }
            BPF_STX => {
                if (ins.k as usize) >= 16 { return SECCOMP_RET_KILL; }
                mem[ins.k as usize] = x; pc += 1;
            }
            BPF_ALU => {
                let v = if src == BPF_X { x } else { ins.k };
                a = match op {
                    BPF_ADD => a.wrapping_add(v),
                    BPF_SUB => a.wrapping_sub(v),
                    BPF_MUL => a.wrapping_mul(v),
                    BPF_OR  => a | v,
                    BPF_AND => a & v,
                    BPF_LSH => if v < 32 { a << v } else { 0 },
                    BPF_RSH => if v < 32 { a >> v } else { 0 },
                    BPF_XOR => a ^ v,
                    BPF_DIV => if v == 0 { 0 } else { a / v },
                    BPF_MOD => if v == 0 { 0 } else { a % v },
                    BPF_NEG => 0u32.wrapping_sub(a),
                    _ => return SECCOMP_RET_KILL,
                };
                pc += 1;
            }
            BPF_JMP => {
                if op == BPF_JA {
                    pc = pc.wrapping_add(1).wrapping_add(ins.k as usize);
                } else {
                    let v = if src == BPF_X { x } else { ins.k };
                    let cond = match op {
                        BPF_JEQ  => a == v,
                        BPF_JGT  => a >  v,
                        BPF_JGE  => a >= v,
                        BPF_JSET => (a & v) != 0,
                        _ => return SECCOMP_RET_KILL,
                    };
                    let off = if cond { ins.jt as usize } else { ins.jf as usize };
                    pc = pc.wrapping_add(1).wrapping_add(off);
                }
            }
            BPF_RET => {
                let v = if src == BPF_X { x } else { ins.k };
                return v;
            }
            BPF_MISC => match op {
                BPF_TAX => { x = a; pc += 1; }
                BPF_TXA => { a = x; pc += 1; }
                _ => return SECCOMP_RET_KILL,
            },
            _ => return SECCOMP_RET_KILL,
        }
    }
    SECCOMP_RET_KILL
}

/// Decode an action priority. Lower numeric value wins.
fn action_priority(rv: u32) -> u32 {
    match rv & SECCOMP_RET_ACTION {
        SECCOMP_RET_KILL  => 0,
        SECCOMP_RET_TRAP  => 1,
        SECCOMP_RET_ERRNO => 2,
        SECCOMP_RET_TRACE => 3,
        SECCOMP_RET_LOG   => 4,
        SECCOMP_RET_ALLOW => 5,
        _                 => 0,
    }
}

/// Called from the syscall dispatch tail. Walks the current task's
/// installed filter chain; if any filter returns non-ALLOW, we
/// short-circuit dispatch.
///
/// Returns:
///   `Ok(())`        — let the call proceed normally.
///   `Err(rv)`       — kernel must return `rv` to the caller (rv is
///                     the substituted i64 return value, e.g.
///                     -EPERM, or — for KILL — the dispatch should
///                     terminate the task).
/// # C: O(F × I) F filters, I instructions per filter
pub fn check(nr: u64, args: &[u64; 6]) -> Result<(), i64> {
    use syscall::errno::Errno;
    let cur = match sched::current() { Some(c) => c, None => return Ok(()) };
    // SAFETY: per-task slot single-mutator per `13§5`; running task on this CPU is the sole writer.
    let filters_ref: &Vec<Vec<u64>> = unsafe { &*cur.seccomp_filters.get() };
    if filters_ref.is_empty() { return Ok(()); }

    let arch = if cfg!(target_arch = "x86_64") { ARCH_X86_64 } else { ARCH_AARCH64 };
    let data = SeccompData {
        nr:   nr as i32,
        arch,
        ip:   0,
        args: *args,
    };

    let mut best_rv: u32 = SECCOMP_RET_ALLOW;
    let mut best_pri: u32 = 5;
    for f in filters_ref.iter() {
        let rv = run_filter(f, &data);
        let pri = action_priority(rv);
        if pri < best_pri {
            best_pri = pri;
            best_rv  = rv;
        }
    }
    match best_rv & SECCOMP_RET_ACTION {
        SECCOMP_RET_ALLOW | SECCOMP_RET_LOG | SECCOMP_RET_TRACE => Ok(()),
        SECCOMP_RET_KILL => {
            // Mark task to terminate — caller treats `Err(LONG_MIN)`
            // as KILL via a sentinel. v1 picks -EPERM as the
            // user-visible side; a real KILL handler would invoke
            // `sys_exit(-1)` in dispatch tail.
            cur.sigpending.fetch_or(1u64 << (9 - 1) /* SIGKILL */, Ordering::Release);
            Err(-(Errno::Eperm.as_i32() as i64))
        }
        SECCOMP_RET_TRAP => {
            cur.sigpending.fetch_or(1u64 << (31 - 1) /* SIGSYS */, Ordering::Release);
            Err(-(Errno::Eperm.as_i32() as i64))
        }
        SECCOMP_RET_ERRNO => {
            let errno = (best_rv & SECCOMP_RET_DATA) as i64;
            Err(if errno > 0 { -errno } else { -(Errno::Eperm.as_i32() as i64) })
        }
        _ => Ok(()),
    }
}

/// `seccomp(op, flags, args)` — slot 317.
/// SECCOMP_SET_MODE_STRICT (0): allow only read/write/_exit/sigreturn.
/// SECCOMP_SET_MODE_FILTER (1): install a cBPF filter from user.
/// SECCOMP_GET_ACTION_AVAIL (2): silent 0 — every action is "available".
/// # C: O(filter_len)
pub fn sys_seccomp(args: &syscall::SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    const SECCOMP_SET_MODE_STRICT: u64 = 0;
    const SECCOMP_SET_MODE_FILTER: u64 = 1;
    const SECCOMP_GET_ACTION_AVAIL: u64 = 2;
    const SOCK_FILTER_BYTES: u64 = 8;
    let op    = args.a0;
    let _flg  = args.a1;
    let arg2  = args.a2;
    let cur = match sched::current() {
        Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
    };
    match op {
        SECCOMP_SET_MODE_STRICT => {
            // Strict mode: a filter that allows exactly read/write/
            // _exit/sigreturn (Linux constants 0/1/60/15) and KILLs
            // everything else. cBPF instruction encoding:
            //   0x20  BPF_LD|W|ABS                 (load A from offset k)
            //   0x15  BPF_JMP|JEQ|K                (if A == k jt else jf)
            //   0x06  BPF_RET|K                    (return k)
            let mk = |code: u16, jt: u8, jf: u8, k: u32|
                encode_filter(SockFilter { code, jt, jf, k });
            let f: Vec<u64> = alloc::vec![
                mk(0x20, 0, 0, 0),                 // A = nr
                mk(0x15, 0, 1, 0),                 // jeq 0(read)
                mk(0x06, 0, 0, SECCOMP_RET_ALLOW),
                mk(0x15, 0, 1, 1),                 // jeq 1(write)
                mk(0x06, 0, 0, SECCOMP_RET_ALLOW),
                mk(0x15, 0, 1, 60),                // jeq 60(_exit)
                mk(0x06, 0, 0, SECCOMP_RET_ALLOW),
                mk(0x15, 0, 1, 15),                // jeq 15(sigreturn)
                mk(0x06, 0, 0, SECCOMP_RET_ALLOW),
                mk(0x06, 0, 0, SECCOMP_RET_KILL),
            ];
            // SAFETY: per-task seccomp_filters slot single-mutator per `13§5`; running task on this CPU.
            unsafe { (*cur.seccomp_filters.get()).push(f); }
            0
        }
        SECCOMP_SET_MODE_FILTER => {
            // arg2 is a `struct sock_fprog { len: u16, filter: *Sock_filter }`.
            if arg2 == 0 || arg2 >= hal::USER_VA_END {
                return -(Errno::Efault.as_i32() as i64);
            }
            // SAFETY: arg2 validated < USER_VA_END; struct sock_fprog layout fixed at 16 bytes; CPL=0 reads.
            let (len_u, filter_p) = unsafe {
                let len = core::ptr::read_volatile(arg2 as *const u16) as usize;
                let filter = core::ptr::read_volatile((arg2 + 8) as *const u64);
                (len, filter)
            };
            if len_u == 0 || len_u > BPF_MAX_INSNS {
                return -(Errno::Einval.as_i32() as i64);
            }
            let total_bytes = (len_u as u64) * SOCK_FILTER_BYTES;
            if filter_p == 0 || filter_p.checked_add(total_bytes).map_or(true, |e| e > hal::USER_VA_END) {
                return -(Errno::Efault.as_i32() as i64);
            }
            let mut prog: Vec<u64> = Vec::with_capacity(len_u);
            // SAFETY: filter range validated < USER_VA_END; len_u × 8 bytes inside the validated range; CPL=0 reads.
            unsafe {
                for i in 0..len_u {
                    let p = filter_p + (i as u64) * SOCK_FILTER_BYTES;
                    let code = core::ptr::read_volatile( p          as *const u16);
                    let jt   = core::ptr::read_volatile((p + 2)     as *const u8);
                    let jf   = core::ptr::read_volatile((p + 3)     as *const u8);
                    let k    = core::ptr::read_volatile((p + 4)     as *const u32);
                    prog.push(encode_filter(SockFilter { code, jt, jf, k }));
                }
            }
            // SAFETY: per-task slot single-mutator per `13§5`; running task on this CPU.
            unsafe { (*cur.seccomp_filters.get()).push(prog); }
            0
        }
        SECCOMP_GET_ACTION_AVAIL => 0,
        _ => -(Errno::Einval.as_i32() as i64),
    }
}
