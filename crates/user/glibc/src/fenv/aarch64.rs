//! fenv aarch64 backend (docs/59§6 G15). FPCR holds rounding (RMode bits
//! 22-23) + per-exception trap-enable bits (IOE=8 DZE=9 OFE=10 UFE=11 IXE=12
//! IDE=15); FPSR holds the cumulative exception flags (IOC=0 DZC=1 OFC=2 UFC=3
//! IXC=4). FE_INVALID..FE_INEXACT = 1/2/4/8/16 map exactly onto FPSR bits 0-4,
//! and the FE_* rounding values (0/0x400000/0x800000/0xc00000) are the FPCR
//! RMode field already shifted to bits 22-23, so most ops are a direct mask.
use super::FE_ROUND_MASK;

/// `fenv_t` — { FPCR, FPSR } (matches aarch64 bits/fenv.h).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct fenv_t {
    pub __fpcr: u32,
    pub __fpsr: u32,
}

/// `femode_t` — control modes = FPCR (rounding + trap-enable). aarch64 glibc
/// uses a single `unsigned int` (the FPCR); modeled as a 1-field struct.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct femode_t {
    pub __fpcr: u32,
}

// FPCR RMode field = bits 22-23 (FE_* round value is already in this position).
const FPCR_RMODE_MASK: u32 = 0x00c0_0000;
// FPCR trap-enable bit positions for IOE/DZE/OFE/UFE/IXE (FPSR flag bit n →
// FPCR enable bit n+8). FE_* flag bits 0-4 shift left by 8.
const FPCR_ENABLE_SHIFT: u32 = 8;

#[inline]
fn read_fpcr() -> u32 {
    let v: u64;
    // SAFETY: mrs reads the FPCR system register into a GPR; no memory touched,
    // architecturally always-readable at EL0, writes only the output operand.
    unsafe { core::arch::asm!("mrs {v}, fpcr", v = out(reg) v, options(nomem, nostack, preserves_flags)); }
    v as u32
}

#[inline]
fn write_fpcr(v: u32) {
    // SAFETY: msr writes the FPCR system register from a GPR; touches no memory,
    // architecturally writable at EL0, only the control register is mutated.
    unsafe { core::arch::asm!("msr fpcr, {v}", v = in(reg) v as u64, options(nomem, nostack, preserves_flags)); }
}

#[inline]
fn read_fpsr() -> u32 {
    let v: u64;
    // SAFETY: mrs reads the FPSR system register into a GPR; no memory touched,
    // architecturally always-readable at EL0, writes only the output operand.
    unsafe { core::arch::asm!("mrs {v}, fpsr", v = out(reg) v, options(nomem, nostack, preserves_flags)); }
    v as u32
}

#[inline]
fn write_fpsr(v: u32) {
    // SAFETY: msr writes the FPSR system register from a GPR; touches no memory,
    // architecturally writable at EL0, only the status register is mutated.
    unsafe { core::arch::asm!("msr fpsr, {v}", v = in(reg) v as u64, options(nomem, nostack, preserves_flags)); }
}

// ---- backend ops consumed by fenv/mod.rs ----

pub(super) fn testexcept() -> i32 { read_fpsr() as i32 & super::FE_ALL_EXCEPT }

pub(super) fn clearexcept(excepts: i32) {
    write_fpsr(read_fpsr() & !((excepts & super::FE_ALL_EXCEPT) as u32));
}

pub(super) fn setexcept(excepts: i32) {
    write_fpsr(read_fpsr() | ((excepts & super::FE_ALL_EXCEPT) as u32));
}

pub(super) fn raiseexcept(excepts: i32) {
    // Setting the cumulative FPSR bits is the observable effect of the op; with
    // traps masked (the default) this matches glibc's portable raise.
    setexcept(excepts);
}

pub(super) fn getround() -> i32 { (read_fpcr() & FPCR_RMODE_MASK) as i32 & FE_ROUND_MASK }

pub(super) fn setround(mode: i32) {
    let r = (mode as u32) & FPCR_RMODE_MASK;
    write_fpcr((read_fpcr() & !FPCR_RMODE_MASK) | r);
}

pub(super) fn getexcept() -> i32 {
    // Enabled = FPCR trap-enable bit set. Shift bits 8-12 back to flag bits 0-4.
    ((read_fpcr() >> FPCR_ENABLE_SHIFT) as i32) & super::FE_ALL_EXCEPT
}

pub(super) fn enableexcept(excepts: i32) {
    let e = (excepts & super::FE_ALL_EXCEPT) as u32;
    write_fpcr(read_fpcr() | (e << FPCR_ENABLE_SHIFT));
}

pub(super) fn disableexcept(excepts: i32) {
    let e = (excepts & super::FE_ALL_EXCEPT) as u32;
    write_fpcr(read_fpcr() & !(e << FPCR_ENABLE_SHIFT));
}

pub(super) fn getenv() -> fenv_t { fenv_t { __fpcr: read_fpcr(), __fpsr: read_fpsr() } }

pub(super) fn setenv(e: &fenv_t) {
    write_fpcr(e.__fpcr);
    write_fpsr(e.__fpsr);
}

pub(super) fn set_default_env() -> i32 {
    // glibc default: round-to-nearest, all traps disabled, flags clear → 0.
    write_fpcr(0);
    write_fpsr(0);
    0
}

pub(super) fn getmode() -> femode_t { femode_t { __fpcr: read_fpcr() } }

pub(super) fn setmode(m: &femode_t) { write_fpcr(m.__fpcr); }

pub(super) fn set_default_mode() -> i32 { write_fpcr(0); 0 }
