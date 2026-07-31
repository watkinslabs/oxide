//! `signalfd_siginfo` rendering: classify a signal record by siginfo(7)
//! layout, then fill ONLY the members that layout defines.
//!
//! No target gate here on purpose (CLAUDE.md "Phantom tests"): the layout
//! decision and every offset are provable by `cargo test -p fs`, and the
//! signalfd file ops are a thin caller.
//!
//! `signalfd_siginfo` is NOT a flat rename of `siginfo_t`. The `_sifields`
//! members of `siginfo_t` are a UNION, so the arm has to be selected from
//! `(si_signo, si_code)` before any member is read; writing pid/uid for, say,
//! a `SIGSEGV` invents a sender that never existed.

use sched::SigInfo;
use sched::signum::{self, Signum};

use super::uapi::*;

/// Linux `enum siginfo_layout` — which `_sifields` union arm a
/// `(signo, si_code)` pair selects.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SigLayout {
    Kill,
    Timer,
    Poll,
    Fault,
    FaultTrapno,
    FaultMceerr,
    FaultBnderr,
    FaultPkuerr,
    FaultPerfEvent,
    Chld,
    Rt,
    Sys,
}

/// `si_code` values that select a layout by themselves (negative half).
const SI_TIMER: i32 = -2;
const SI_SIGIO: i32 = -5;

/// Per-signal `si_code` upper bounds (Linux `sig_sicodes[].limit`). A code
/// above the bound is not a signal-specific code, so the pair falls back to
/// `SIL_POLL`/`SIL_KILL` rather than the signal's own arm.
const NSIGILL:  i32 = 11;
const NSIGFPE:  i32 = 15;
const NSIGSEGV: i32 = 10;
const NSIGBUS:  i32 = 5;
const NSIGTRAP: i32 = 6;
const NSIGCHLD: i32 = 6;
const NSIGPOLL: i32 = 6;
const NSIGSYS:  i32 = 2;

/// Signal-specific `si_code`s that override their signal's default arm.
const BUS_MCEERR_AR: i32 = 4;
const BUS_MCEERR_AO: i32 = 5;
const SEGV_BNDERR:   i32 = 3;
const SEGV_PKUERR:   i32 = 4;
const TRAP_PERF:     i32 = 6;

/// Signal-specific arm and code bound for `signo`, when it has one.
/// # C: O(1)
fn sig_sicode(signo: u32) -> Option<(i32, SigLayout)> {
    match signo {
        s if s == Signum::Sigill  as u32 => Some((NSIGILL,  SigLayout::Fault)),
        s if s == Signum::Sigfpe  as u32 => Some((NSIGFPE,  SigLayout::Fault)),
        s if s == Signum::Sigsegv as u32 => Some((NSIGSEGV, SigLayout::Fault)),
        s if s == Signum::Sigbus  as u32 => Some((NSIGBUS,  SigLayout::Fault)),
        s if s == Signum::Sigtrap as u32 => Some((NSIGTRAP, SigLayout::Fault)),
        s if s == Signum::Sigchld as u32 => Some((NSIGCHLD, SigLayout::Chld)),
        s if s == Signum::Sigio   as u32 => Some((NSIGPOLL, SigLayout::Poll)),
        s if s == Signum::Sigsys  as u32 => Some((NSIGSYS,  SigLayout::Sys)),
        _ => None,
    }
}

/// Linux `siginfo_layout(sig, si_code)`. # C: O(1)
pub fn siginfo_layout(signo: u32, si_code: i32) -> SigLayout {
    if si_code > signum::SI_USER && si_code < signum::SI_KERNEL {
        if let Some((limit, layout)) = sig_sicode(signo) {
            if si_code <= limit {
                if signo == Signum::Sigbus as u32
                    && (BUS_MCEERR_AR..=BUS_MCEERR_AO).contains(&si_code) {
                    return SigLayout::FaultMceerr;
                }
                if signo == Signum::Sigsegv as u32 && si_code == SEGV_BNDERR {
                    return SigLayout::FaultBnderr;
                }
                if signo == Signum::Sigsegv as u32 && si_code == SEGV_PKUERR {
                    return SigLayout::FaultPkuerr;
                }
                if signo == Signum::Sigtrap as u32 && si_code == TRAP_PERF {
                    return SigLayout::FaultPerfEvent;
                }
                return layout;
            }
        }
        if si_code <= NSIGPOLL { return SigLayout::Poll; }
        return SigLayout::Kill;
    }
    if si_code == SI_TIMER { return SigLayout::Timer; }
    if si_code == SI_SIGIO { return SigLayout::Poll; }
    if si_code < 0 { return SigLayout::Rt; }
    SigLayout::Kill
}

fn put_u16(out: &mut [u8], off: usize, v: u16) { out[off..off + 2].copy_from_slice(&v.to_ne_bytes()); }
fn put_u32(out: &mut [u8], off: usize, v: u32) { out[off..off + 4].copy_from_slice(&v.to_ne_bytes()); }
fn put_i32(out: &mut [u8], off: usize, v: i32) { out[off..off + 4].copy_from_slice(&v.to_ne_bytes()); }
fn put_u64(out: &mut [u8], off: usize, v: u64) { out[off..off + 8].copy_from_slice(&v.to_ne_bytes()); }

/// Render one 128-byte `signalfd_siginfo` into `out`.
///
/// `rec` is `None` for a bitmap-only signal (the pending bit was set by a
/// source that queues no record); only `ssi_signo` is then meaningful, and
/// every other member stays zero — the same shape Linux produces for a
/// `SEND_SIG_NOINFO` signal whose `si_code` is `SI_USER` and whose sender
/// fields are zero.
/// # C: O(1)
pub fn encode(signo: u32, rec: Option<&SigInfo>, out: &mut [u8]) {
    for b in &mut out[..SIGINFO_SIZE] { *b = 0; }
    put_u32(out, SSI_SIGNO, signo);
    let Some(r) = rec else { return };
    put_i32(out, SSI_CODE, r.code);
    // The `_sigsys` arm carries its own `si_errno` (the seccomp filter's
    // 16-bit data). Every other arm this kernel produces leaves it 0.
    if let Some(s) = r.sys {
        put_i32(out, SSI_ERRNO, s.errno);
        put_u64(out, SSI_CALL_ADDR, s.call_addr);
        put_i32(out, SSI_SYSCALL, s.syscall);
        put_u32(out, SSI_ARCH, s.arch);
        return;
    }
    match siginfo_layout(signo, r.code) {
        SigLayout::Kill => {
            put_u32(out, SSI_PID, r.pid);
            put_u32(out, SSI_UID, r.uid);
        }
        SigLayout::Timer => {
            // `_timer` overlays `_kill`: `si_tid` shares `si_pid`'s bytes and
            // `si_overrun` shares `si_uid`'s.
            put_u32(out, SSI_TID, r.pid);
            put_u32(out, SSI_OVERRUN, r.uid);
            put_u64(out, SSI_PTR, r.value);
            put_i32(out, SSI_INT, r.value as i32);
        }
        SigLayout::Poll => {
            // `_sigpoll`: `long si_band` covers both `_kill` words, `int
            // si_fd` follows in the `si_value` slot. A record produced by the
            // async-I/O path carries the real `_sigpoll` arm; the overlaid
            // reconstruction is the fallback for a record that predates it (a
            // user-forged `rt_sigqueueinfo` whose si_code selects this layout).
            let (band, fd) = match r.poll {
                Some(q) => (q.band as u32, q.fd),
                None    => (r.pid, r.value as i32),
            };
            put_u32(out, SSI_BAND, band);
            put_i32(out, SSI_FD, fd);
        }
        SigLayout::Fault | SigLayout::FaultBnderr | SigLayout::FaultPkuerr
        | SigLayout::FaultPerfEvent => {
            put_u64(out, SSI_ADDR, fault_addr(r));
        }
        SigLayout::FaultTrapno => {
            put_u64(out, SSI_ADDR, fault_addr(r));
            put_u32(out, SSI_TRAPNO, r.value as u32);
        }
        SigLayout::FaultMceerr => {
            put_u64(out, SSI_ADDR, fault_addr(r));
            put_u16(out, SSI_ADDR_LSB, fault_addr_lsb(r));
        }
        SigLayout::Chld => {
            put_u32(out, SSI_PID, r.pid);
            put_u32(out, SSI_UID, r.uid);
            put_i32(out, SSI_STATUS, r.value as i32);
        }
        SigLayout::Rt => {
            put_u32(out, SSI_PID, r.pid);
            put_u32(out, SSI_UID, r.uid);
            put_u64(out, SSI_PTR, r.value);
            put_i32(out, SSI_INT, r.value as i32);
        }
        SigLayout::Sys => {
            // `SIGSYS` without the dedicated payload: the union words still
            // hold `_sigsys`, so read them through the same overlay.
            put_u64(out, SSI_CALL_ADDR, fault_addr(r));
            put_i32(out, SSI_SYSCALL, r.value as i32);
            put_u32(out, SSI_ARCH, (r.value >> 32) as u32);
        }
    }
}

/// The first 8 `_sifields` bytes as one member.
///
/// A queued record's `pid`/`uid`/`value` are the `_sifields` union words at
/// byte 16, 20 and 24 of `siginfo_t` — the same bytes the signal-frame writer
/// emits — so an arm whose first member is 8 bytes wide (`_sigfault.si_addr`,
/// `_sigpoll.si_band`, `_sigsys._call_addr`) is exactly the two 4-byte words
/// joined low half first.
/// # C: O(1)
/// `_sigfault._addr`. A record produced by `force_sig_fault` carries the real
/// `_sigfault` arm; the pid/uid reconstruction is the fallback for a record
/// that predates it (a user-forged `rt_sigqueueinfo` whose si_code happens to
/// select a fault layout), where those two words ARE the overlaid si_addr.
/// # C: O(1)
fn fault_addr(r: &SigInfo) -> u64 {
    match r.fault { Some(f) => f.addr, None => (r.pid as u64) | ((r.uid as u64) << 32) }
}

/// `_sigfault._addr_lsb` — the `short` the SIGBUS machine-check codes carry.
/// # C: O(1)
fn fault_addr_lsb(r: &SigInfo) -> u16 {
    match r.fault { Some(f) => f.addr_lsb as u16, None => r.value as u16 }
}

#[cfg(test)]
mod tests;
