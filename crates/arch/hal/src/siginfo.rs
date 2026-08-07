// `siginfo_t` construction shared by both arches' `build_signal_frame` and by
// every syscall that copies a signal record out to userspace. Split from
// `lib.rs` per `08§7`.
//
// The union arms OVERLAP (`_kill`, `_sigchld`, `_rt`, `_sigsys` all start at
// `_sifields`, byte 16), so the arm must be selected before any field is
// written — one writer here so the two arches cannot drift.
//
// Three sides, ONE owner:
//   * PRODUCER — a record built in the kernel names its arm directly (the
//     `Option` members of `SigPayload`), exactly as a kernel producer assigns
//     one union member. `write_siginfo` renders it.
//   * DECODER  — a FLAT 128-byte record (from userspace, or read back out of a
//     buffer) carries no such tag, so its arm is derived from
//     `(si_signo, si_code)` by [`layout`]. `read_siginfo` renders that.
//   * CLASSIFIER — [`layout`] is also what `signalfd_siginfo` rendering keys
//     on, so a `_sigfault` record cannot be a `_kill` one on one path and a
//     fault on another.
//
// Ungated on purpose (`CLAUDE.md` phantom-test rule): every rule below is a
// decision provable by `cargo test -p hal`.

/// Extra siginfo_t payload an SA_SIGINFO handler reads, passed
/// arch-neutrally from the signal-delivery path into the per-arch
/// `build_signal_frame` so it can populate the `_sifields` union
/// (`27§5`, siginfo(7)). POD so it crosses the HAL boundary without a
/// crate cycle (sched/fs/hal all share this one type).
///
/// `code`→si_code, `pid`→si_pid, `uid`→si_uid are common to both union
/// arms. The +24 slot is the arm discriminator:
///   `chld_arm` — `_sigchld`: `status`→si_status (`int`, 4 bytes).
///   otherwise  — `_rt`: `value`→si_value (`sigval_t`, a full 8 bytes).
/// Truncating an `_rt` si_value to 4 bytes loses `sival_ptr`, which
/// `sigqueue(3)`/`timer_create(2)` callers dereference.
///
/// `sigsys` selects a THIRD arm and, when present, overrides both of the
/// above: see `Sigsys`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct SigPayload {
    pub code:   i32,
    pub pid:    i32,
    pub uid:    u32,
    pub status: i32,
    pub value:  u64,
    pub chld_arm: bool,
    /// `_sigsys` arm — `Some` only for a seccomp-raised `SIGSYS`.
    pub sigsys: Option<Sigsys>,
    /// `_sigfault` arm — `Some` for every synchronous fault signal
    /// (SIGSEGV/SIGBUS/SIGILL/SIGFPE/SIGTRAP). Overrides `_kill`/`_rt` the same
    /// way `sigsys` does: the arms overlap at `_sifields`.
    pub fault: Option<SigFault>,
    /// `_sigpoll` arm — `Some` for an async-I/O readiness signal raised by
    /// `fcntl(F_SETOWN)`/`O_ASYNC` (and by `F_SETSIG`'s chosen signal).
    /// Overlaps `_kill`/`_rt`/`_sigfault` at `_sifields`.
    pub poll: Option<SigPoll>,
}

/// `siginfo_t::_sifields._sigpoll` — the arm `SIGPOLL`/`SIGIO` (and any
/// `F_SETSIG` replacement) selects (`include/uapi/asm-generic/siginfo.h`).
///
/// `si_band` is an `__ARCH_SI_BAND_T` = `long` on both x86_64 and aarch64, so
/// it covers the two 4-byte words `si_pid`/`si_uid` occupy, and `si_fd` follows
/// in `si_value`'s first 4 bytes. Without this arm an `SA_SIGINFO` SIGIO
/// handler reads `si_fd == 0` and cannot tell WHICH descriptor became ready —
/// the whole reason `F_SETSIG` exists.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct SigPoll {
    /// `si_band` — the poll mask that fired, per Linux's `band_table`.
    pub band: i64,
    /// `si_fd` — the descriptor number recorded when `O_ASYNC` was enabled.
    pub fd: i32,
}

/// `siginfo_t::_sifields._sigfault` — the arm SIGSEGV, SIGBUS, SIGILL, SIGFPE
/// and SIGTRAP select (`include/uapi/asm-generic/siginfo.h`).
///
/// `addr` is the faulting instruction / memory reference. `addr_lsb` is the
/// `short` that follows it, meaningful for the SIGBUS machine-check codes; the
/// remaining inner-union members (`_addr_bnd`, `_addr_pkey`, `_perf`) start
/// past it and are written by their own producers.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct SigFault {
    /// `si_addr`.
    pub addr: u64,
    /// `si_addr_lsb` — log2 of the reported page size for the SIGBUS
    /// machine-check codes; 0 everywhere else.
    pub addr_lsb: i16,
}

/// `siginfo_t::_sifields._sigsys` (`include/uapi/asm-generic/siginfo.h`),
/// filled by `force_sig_seccomp` (`kernel/signal.c`) for both
/// `SECCOMP_RET_TRAP` and the `SECCOMP_RET_KILL_*` core dump. A `SIGSYS`
/// handler reads `si_syscall`/`si_arch` to decide which call was rejected,
/// and `si_errno` is the filter's own 16-bit data — all zero without this.
///
/// POD in `hal` so `security` (which computes it), `sched` (which queues it)
/// and the per-arch frame builders (which write it) share ONE definition.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Sigsys {
    /// `si_call_addr` — `KSTK_EIP(current)`, the user PC of the trapped call.
    pub call_addr: u64,
    /// `si_syscall` — the syscall number AS THE CALLING ABI NUMBERS IT.
    pub syscall: i32,
    /// `si_arch` — `syscall_get_arch()`, an `AUDIT_ARCH_*` token.
    pub arch: u32,
    /// `si_errno` — `SECCOMP_RET_DATA`, the filter's low 16 bits.
    pub errno: i32,
}

/// `si_code` values for the `_sigfault` signals (`asm-generic/siginfo.h`).
/// The ONE owner: every fault classifier and every test names a constant here
/// instead of open-coding `1`/`2` (`07§5`).
pub mod code {
    /// SIGSEGV — address not mapped to object.
    pub const SEGV_MAPERR: i32 = 1;
    /// SIGSEGV — invalid permissions for mapped object.
    pub const SEGV_ACCERR: i32 = 2;
    /// SIGSEGV — failed address bound checks.
    pub const SEGV_BNDERR: i32 = 3;
    /// SIGSEGV — failed protection-key check.
    pub const SEGV_PKUERR: i32 = 4;
    /// SIGSEGV — control-protection fault (shadow stack / indirect branch).
    pub const SEGV_CPERR: i32 = 10;
    /// SIGBUS — invalid address alignment.
    pub const BUS_ADRALN: i32 = 1;
    /// SIGBUS — non-existent physical address.
    pub const BUS_ADRERR: i32 = 2;
    /// SIGBUS — object-specific hardware error (SIGBUS past EOF on a file map).
    pub const BUS_OBJERR: i32 = 3;
    /// SIGILL — illegal opcode.
    pub const ILL_ILLOPC: i32 = 1;
    /// SIGILL — illegal operand.
    pub const ILL_ILLOPN: i32 = 2;
    /// SIGILL — illegal addressing mode.
    pub const ILL_ILLADR: i32 = 3;
    /// SIGILL — illegal trap.
    pub const ILL_ILLTRP: i32 = 4;
    /// SIGILL — privileged opcode.
    pub const ILL_PRVOPC: i32 = 5;
    /// SIGILL — privileged register.
    pub const ILL_PRVREG: i32 = 6;
    /// SIGILL — coprocessor error.
    pub const ILL_COPROC: i32 = 7;
    /// SIGILL — internal stack error.
    pub const ILL_BADSTK: i32 = 8;
    /// SIGFPE — integer divide by zero.
    pub const FPE_INTDIV: i32 = 1;
    /// SIGFPE — integer overflow.
    pub const FPE_INTOVF: i32 = 2;
    /// SIGFPE — floating-point divide by zero.
    pub const FPE_FLTDIV: i32 = 3;
    /// SIGFPE — floating-point overflow.
    pub const FPE_FLTOVF: i32 = 4;
    /// SIGFPE — floating-point underflow.
    pub const FPE_FLTUND: i32 = 5;
    /// SIGFPE — floating-point inexact result.
    pub const FPE_FLTRES: i32 = 6;
    /// SIGFPE — floating-point invalid operation.
    pub const FPE_FLTINV: i32 = 7;
    /// SIGFPE — subscript out of range.
    pub const FPE_FLTSUB: i32 = 8;
    /// SIGFPE — undiagnosed floating-point exception.
    pub const FPE_FLTUNK: i32 = 14;
    /// SIGTRAP — process breakpoint (`int3` / `brk`).
    pub const TRAP_BRKPT: i32 = 1;
    /// SIGTRAP — single-step / trace trap.
    pub const TRAP_TRACE: i32 = 2;
    /// SIGTRAP — hardware breakpoint / watchpoint.
    pub const TRAP_HWBKPT: i32 = 4;
    /// SIGTRAP — undiagnosed trap.
    pub const TRAP_UNK: i32 = 5;
    /// SIGTRAP — `perf_event_open` sample with `sigtrap=1`; selects the
    /// `_perf` inner union rather than the plain `_sigfault` one.
    pub const TRAP_PERF: i32 = 6;
}

/// Signal numbers the union-arm decision keys on. Identical on x86_64 and
/// aarch64 (both take the asm-generic numbering), and duplicated here rather
/// than imported so `hal` keeps no dependency on `sched`.
pub mod signo {
    pub const SIGILL:  u32 = 4;
    pub const SIGTRAP: u32 = 5;
    pub const SIGBUS:  u32 = 7;
    pub const SIGFPE:  u32 = 8;
    pub const SIGSEGV: u32 = 11;
    pub const SIGCHLD: u32 = 17;
    /// `SIGPOLL` is the same number.
    pub const SIGIO:   u32 = 29;
    pub const SIGSYS:  u32 = 31;
}

/// `si_code` values that name a SOURCE rather than a signal-specific
/// condition. The window `SI_USER < code < SI_KERNEL` is what makes a code
/// signal-specific; everything outside it is classified by source alone.
pub mod source {
    /// `kill(2)`, `raise(3)`, `sigsend`.
    pub const SI_USER:   i32 = 0;
    /// Raised by the kernel from somewhere with no better classification.
    pub const SI_KERNEL: i32 = 0x80;
    /// `timer_create(2)` expiry — selects the `_timer` arm.
    pub const SI_TIMER:  i32 = -2;
    /// A queued `SIGIO` — selects `_sigpoll` even though the code is negative.
    pub const SI_SIGIO:  i32 = -5;
    /// `execve` killing a sibling thread.
    pub const SI_DETHREAD: i32 = -7;
    /// Asynchronous name-lookup completion.
    pub const SI_ASYNCNL: i32 = -60;
}

/// Per-signal `si_code` upper bound (Linux `sig_sicodes[].limit`). A code above
/// its signal's bound is not signal-specific, so the pair falls back to
/// `_sigpoll`/`_kill` rather than the signal's own arm.
pub mod limit {
    pub const NSIGILL:  i32 = 11;
    pub const NSIGFPE:  i32 = 15;
    pub const NSIGSEGV: i32 = 10;
    pub const NSIGBUS:  i32 = 5;
    pub const NSIGTRAP: i32 = 6;
    pub const NSIGCHLD: i32 = 6;
    pub const NSIGPOLL: i32 = 6;
    pub const NSIGSYS:  i32 = 2;
}

/// Which `_sifields` union arm a `(si_signo, si_code)` pair selects — Linux
/// `enum siginfo_layout`.
///
/// The four `Fault*` variants all put `si_addr` at `_sifields`; they differ
/// only in what follows it, so every one of them is decoded through the
/// `_sigfault` arm and the extra members belong to their own producers.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Layout {
    Kill,
    Timer,
    Poll,
    Fault,
    /// `si_trapno` after `si_addr` — SPARC/Alpha only, never produced here.
    FaultTrapno,
    /// `si_addr_lsb` after `si_addr` (the SIGBUS machine-check codes).
    FaultMceerr,
    FaultBnderr,
    FaultPkuerr,
    FaultPerfEvent,
    Chld,
    Rt,
    Sys,
}

impl Layout {
    /// Whether this layout's `_sifields` is the `_sigfault` arm — i.e. bytes
    /// 16..24 are `si_addr` and NOT `si_pid`/`si_uid`.
    /// # C: O(1)
    pub fn is_fault(self) -> bool {
        matches!(self, Layout::Fault | Layout::FaultTrapno | Layout::FaultMceerr
                     | Layout::FaultBnderr | Layout::FaultPkuerr | Layout::FaultPerfEvent)
    }
}

/// Signal-specific arm and code bound for `sig`, when it has one.
/// # C: O(1)
fn sig_sicode(sig: u32) -> Option<(i32, Layout)> {
    match sig {
        signo::SIGILL  => Some((limit::NSIGILL,  Layout::Fault)),
        signo::SIGFPE  => Some((limit::NSIGFPE,  Layout::Fault)),
        signo::SIGSEGV => Some((limit::NSIGSEGV, Layout::Fault)),
        signo::SIGBUS  => Some((limit::NSIGBUS,  Layout::Fault)),
        signo::SIGTRAP => Some((limit::NSIGTRAP, Layout::Fault)),
        signo::SIGCHLD => Some((limit::NSIGCHLD, Layout::Chld)),
        signo::SIGIO   => Some((limit::NSIGPOLL, Layout::Poll)),
        signo::SIGSYS  => Some((limit::NSIGSYS,  Layout::Sys)),
        _ => None,
    }
}

/// Whether a user-supplied `(signal, si_code)` has a layout whose 48-byte
/// kernel prefix contains every meaningful field. Unknown layouts may carry
/// future data in siginfo_t's expansion and must preserve it or reject it.
/// # C: O(1)
pub fn known_layout(sig: u32, si_code: i32) -> bool {
    if si_code == source::SI_KERNEL { return true; }
    if si_code > source::SI_USER {
        return match sig_sicode(sig) {
            Some((bound, _)) => si_code <= bound,
            None => si_code <= limit::NSIGPOLL,
        };
    }
    si_code >= source::SI_DETHREAD || si_code == source::SI_ASYNCNL
}

/// `si_code` values that override their signal's default fault arm.
const BUS_MCEERR_AR: i32 = 4;
const BUS_MCEERR_AO: i32 = 5;

/// Linux `siginfo_layout(sig, si_code)` — the ONE owner of "which union arm
/// does this record use". A record whose arm is decided anywhere else can
/// disagree with the one a handler reads, which is how a fault reports as a
/// kill.
/// # C: O(1)
pub fn layout(sig: u32, si_code: i32) -> Layout {
    if si_code > source::SI_USER && si_code < source::SI_KERNEL {
        if let Some((bound, arm)) = sig_sicode(sig) {
            if si_code <= bound {
                if sig == signo::SIGBUS && (BUS_MCEERR_AR..=BUS_MCEERR_AO).contains(&si_code) {
                    return Layout::FaultMceerr;
                }
                if sig == signo::SIGSEGV && si_code == code::SEGV_BNDERR { return Layout::FaultBnderr; }
                if sig == signo::SIGSEGV && si_code == code::SEGV_PKUERR { return Layout::FaultPkuerr; }
                if sig == signo::SIGTRAP && si_code == code::TRAP_PERF { return Layout::FaultPerfEvent; }
                return arm;
            }
        }
        if si_code <= limit::NSIGPOLL { return Layout::Poll; }
        return Layout::Kill;
    }
    if si_code == source::SI_TIMER { return Layout::Timer; }
    if si_code == source::SI_SIGIO { return Layout::Poll; }
    if si_code < 0 { return Layout::Rt; }
    Layout::Kill
}

/// siginfo_t field offsets (`asm-generic/siginfo.h`) — identical on x86_64 and
/// aarch64, so both frame builders share one writer.
const SI_SIGNO: usize = 0;
/// `int si_errno`, between si_signo and si_code. Only the `_sigsys` arm uses
/// it; every other path leaves it 0.
const SI_ERRNO: usize = 4;
const SI_CODE:  usize = 8;
const SI_PID:   usize = 16;
const SI_UID:   usize = 20;
/// `_sigchld.si_status` (`int`) and `_rt.si_value` (`sigval_t`) both start
/// here; only their WIDTH differs.
const SI_VALUE: usize = 24;
/// `_sigsys._call_addr` (`void __user *`) starts at `_sifields`, i.e. the same
/// byte as si_pid — the union arms overlap, which is why the arm must be
/// selected before anything is written.
const SI_CALL_ADDR: usize = 16;
const SI_SYSCALL:   usize = 24;
const SI_ARCH:      usize = 28;
/// `_sigfault._addr` — also at `_sifields`, overlapping si_pid/si_call_addr.
const SI_ADDR:      usize = 16;
/// `_sigfault._addr_lsb`, the `short` in the inner union right after `_addr`.
const SI_ADDR_LSB:  usize = 24;
/// `_sigpoll._band` (`long`) — also at `_sifields`, overlapping si_pid/si_uid.
const SI_BAND:      usize = 16;
/// `_sigpoll._fd` (`int`), immediately after the 8-byte `_band`.
const SI_FD:        usize = 24;

/// Fill a signal frame's 128-byte `siginfo_t` from an arch-neutral payload.
/// Shared by both `build_signal_frame`s so the two arches cannot drift on the
/// union arms an SA_SIGINFO handler reads.
/// # C: O(1)
pub fn write_siginfo(info: &mut [u8; 128], sig: u32, payload: Option<SigPayload>) {
    info[SI_SIGNO..SI_SIGNO + 4].copy_from_slice(&(sig as i32).to_ne_bytes());
    let Some(p) = payload else { return };
    info[SI_CODE..SI_CODE + 4].copy_from_slice(&p.code.to_ne_bytes());
    if let Some(s) = p.sigsys {
        info[SI_ERRNO..SI_ERRNO + 4].copy_from_slice(&s.errno.to_ne_bytes());
        info[SI_CALL_ADDR..SI_CALL_ADDR + 8].copy_from_slice(&s.call_addr.to_ne_bytes());
        info[SI_SYSCALL..SI_SYSCALL + 4].copy_from_slice(&s.syscall.to_ne_bytes());
        info[SI_ARCH..SI_ARCH + 4].copy_from_slice(&s.arch.to_ne_bytes());
        return;
    }
    if let Some(f) = p.fault {
        info[SI_ADDR..SI_ADDR + 8].copy_from_slice(&f.addr.to_ne_bytes());
        info[SI_ADDR_LSB..SI_ADDR_LSB + 2].copy_from_slice(&f.addr_lsb.to_ne_bytes());
        return;
    }
    if let Some(q) = p.poll {
        info[SI_BAND..SI_BAND + 8].copy_from_slice(&q.band.to_ne_bytes());
        info[SI_FD..SI_FD + 4].copy_from_slice(&q.fd.to_ne_bytes());
        return;
    }
    info[SI_PID..SI_PID + 4].copy_from_slice(&p.pid.to_ne_bytes());
    info[SI_UID..SI_UID + 4].copy_from_slice(&p.uid.to_ne_bytes());
    if p.chld_arm {
        info[SI_VALUE..SI_VALUE + 4].copy_from_slice(&p.status.to_ne_bytes());
    } else {
        info[SI_VALUE..SI_VALUE + 8].copy_from_slice(&p.value.to_ne_bytes());
    }
}

fn i32_at(b: &[u8], off: usize) -> i32 { i32::from_ne_bytes([b[off], b[off+1], b[off+2], b[off+3]]) }
fn u32_at(b: &[u8], off: usize) -> u32 { i32_at(b, off) as u32 }
fn u64_at(b: &[u8], off: usize) -> u64 {
    let mut w = [0u8; 8];
    w.copy_from_slice(&b[off..off + 8]);
    u64::from_ne_bytes(w)
}

/// Decode a FLAT `siginfo_t` (Linux `copy_siginfo_from_user`) into the
/// arm-tagged payload the rest of the kernel carries.
///
/// Linux's `kernel_siginfo_t` IS the union, so its copy-in is a straight
/// `copy_from_user` and the arm survives untouched. Ours is a decomposed
/// struct, so the arm has to be recovered — from `(sig, si_code)`, the only
/// thing the bytes say about it. Reading `si_pid`/`si_uid` unconditionally is
/// what turns a `_sigfault` record's `si_addr` into a sender that never
/// existed.
///
/// `sig` overrides whatever `si_signo` the buffer holds, matching
/// `__copy_siginfo_from_user`: the syscall's signal argument wins.
/// # C: O(1)
pub fn read_siginfo(info: &[u8; 128], sig: u32) -> SigPayload {
    let code = i32_at(info, SI_CODE);
    let arm = layout(sig, code);
    let mut p = SigPayload { code, ..Default::default() };
    if arm == Layout::Sys {
        p.sigsys = Some(Sigsys {
            call_addr: u64_at(info, SI_CALL_ADDR),
            syscall:   i32_at(info, SI_SYSCALL),
            arch:      u32_at(info, SI_ARCH),
            errno:     i32_at(info, SI_ERRNO),
        });
        return p;
    }
    if arm.is_fault() {
        p.fault = Some(SigFault {
            addr:     u64_at(info, SI_ADDR),
            addr_lsb: i16::from_ne_bytes([info[SI_ADDR_LSB], info[SI_ADDR_LSB + 1]]),
        });
        return p;
    }
    if arm == Layout::Poll {
        p.poll = Some(SigPoll { band: u64_at(info, SI_BAND) as i64, fd: i32_at(info, SI_FD) });
        return p;
    }
    p.pid = i32_at(info, SI_PID);
    p.uid = u32_at(info, SI_UID);
    // `_sigchld.si_status` is an `int`; the four bytes past it belong to
    // `si_utime` and must not be folded into an 8-byte `si_value`.
    if arm == Layout::Chld {
        p.chld_arm = true;
        p.status = i32_at(info, SI_VALUE);
        p.value  = p.status as u32 as u64;
    } else {
        p.value  = u64_at(info, SI_VALUE);
        p.status = p.value as i32;
    }
    p
}

#[cfg(test)]
#[path = "siginfo/tests.rs"] mod tests;
