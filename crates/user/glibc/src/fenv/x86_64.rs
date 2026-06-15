//! fenv x86_64 backend (docs/59§6 G15). Operates the SSE MXCSR (the unit real
//! SSE2 code uses) and mirrors the legacy x87 control+status word so fstenv-
//! based `fenv_t` round-trips like glibc. MXCSR layout: bits 0-5 exception
//! flags (IE/DE/ZE/OE/UE/PE), bit 6 DAZ, bits 7-12 exception masks, bits 13-14
//! rounding, bit 15 FTZ. x87 control word: bits 0-5 masks, bits 10-11 round;
//! x87 status word bits 0-5 exception flags. FE_* values equal the x87 bit
//! positions, so on x86 the FE_* mask IS the MXCSR/x87 exception bitfield.
use super::{FE_ROUND_MASK, FE_TONEAREST};

/// `fenv_t` — fstenv block + MXCSR (matches x86_64 bits/fenv.h byte layout).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct fenv_t {
    pub __control_word: u16,
    __reserved1: u16,
    pub __status_word: u16,
    __reserved2: u16,
    __tags: u16,
    __reserved3: u16,
    __eip: u32,
    __cs_selector: u16,
    __opcode: u16, // __opcode:11 + __reserved4:5 packed into one u16-pair slot
    __data_offset: u32,
    __data_selector: u16,
    __reserved5: u16,
    pub __mxcsr: u32,
}

/// `femode_t` — control word + MXCSR (matches x86_64 bits/fenv.h).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct femode_t {
    pub __control_word: u16,
    __reserved: u16,
    pub __mxcsr: u32,
}

// MXCSR field shifts.
const MXCSR_ROUND_SHIFT: u32 = 13; // FE_* round value (0/0x400/0x800/0xc00) → bits 13-14
const MXCSR_MASK_SHIFT: u32 = 7; // exception-mask bits 7-12 mirror flag bits 0-5
const X87_ROUND_SHIFT: u32 = 10; // x87 control-word round bits 10-11

#[inline]
fn read_mxcsr() -> u32 {
    let mut v: u32 = 0;
    // SAFETY: stmxcsr stores the 32-bit MXCSR into the provided 4-byte stack
    // slot; reads no other memory, writes only `v`, present on every SSE2 CPU.
    unsafe { core::arch::asm!("stmxcsr [{p}]", p = in(reg) &mut v, options(nostack, preserves_flags)); }
    v
}

#[inline]
fn write_mxcsr(v: u32) {
    // SAFETY: ldmxcsr loads the 32-bit MXCSR from the provided 4-byte stack
    // slot; reads only `v`, writes the control register, valid on all SSE2 CPUs.
    unsafe { core::arch::asm!("ldmxcsr [{p}]", p = in(reg) &v, options(nostack, preserves_flags)); }
}

#[inline]
fn read_x87cw() -> u16 {
    let mut v: u16 = 0;
    // SAFETY: fnstcw stores the 16-bit x87 control word into the 2-byte stack
    // slot; reads no other memory, writes only `v`, present on all x86_64 FPUs.
    unsafe { core::arch::asm!("fnstcw [{p}]", p = in(reg) &mut v, options(nostack, preserves_flags)); }
    v
}

#[inline]
fn write_x87cw(v: u16) {
    // SAFETY: fldcw loads the 16-bit x87 control word from the 2-byte stack
    // slot; reads only `v`, writes the x87 control register, valid on x86_64.
    unsafe { core::arch::asm!("fldcw [{p}]", p = in(reg) &v, options(nostack, preserves_flags)); }
}

#[inline]
fn read_x87sw() -> u16 {
    let mut v: u16 = 0;
    // SAFETY: fnstsw stores the 16-bit x87 status word into the 2-byte stack
    // slot; reads no other memory, writes only `v`, present on all x86_64 FPUs.
    unsafe { core::arch::asm!("fnstsw [{p}]", p = in(reg) &mut v, options(nostack, preserves_flags)); }
    v
}

#[inline]
fn clear_x87_flags() {
    // SAFETY: fnclex clears the x87 exception-status flags without raising any
    // pending exception; touches no memory, only the x87 status register.
    unsafe { core::arch::asm!("fnclex", options(nostack, preserves_flags)); }
}

// ---- backend ops consumed by fenv/mod.rs ----

pub(super) fn testexcept() -> i32 {
    // OR the SSE and x87 cumulative flags (both bits 0-5 = FE_* layout).
    ((read_mxcsr() as i32) | (read_x87sw() as i32)) & super::FE_ALL_EXCEPT
}

pub(super) fn clearexcept(excepts: i32) {
    let m = read_mxcsr() & !((excepts & super::FE_ALL_EXCEPT) as u32);
    write_mxcsr(m);
    if read_x87sw() as i32 & super::FE_ALL_EXCEPT & excepts != 0 {
        // x87 status has no per-flag clear; fnclex wipes all, then nothing to
        // restore since only flags (not data) are affected.
        clear_x87_flags();
    }
}

pub(super) fn setexcept(excepts: i32) {
    // Set the cumulative flag bits without trapping: OR into MXCSR (masked).
    let m = read_mxcsr() | ((excepts & super::FE_ALL_EXCEPT) as u32);
    write_mxcsr(m);
}

pub(super) fn raiseexcept(excepts: i32) {
    // Setting the masked MXCSR flag bits has the same observable cumulative
    // effect as executing the trapping op (glibc's portable raise path).
    setexcept(excepts);
}

pub(super) fn getround() -> i32 {
    ((read_mxcsr() >> MXCSR_ROUND_SHIFT) as i32 & 0x3) << 10 & FE_ROUND_MASK
}

pub(super) fn setround(mode: i32) {
    let r = ((mode & FE_ROUND_MASK) >> 10) as u32 & 0x3;
    let m = (read_mxcsr() & !(0x3 << MXCSR_ROUND_SHIFT)) | (r << MXCSR_ROUND_SHIFT);
    write_mxcsr(m);
    let cw = (read_x87cw() & !(0x3 << X87_ROUND_SHIFT)) | ((r as u16) << X87_ROUND_SHIFT);
    write_x87cw(cw);
}

pub(super) fn getexcept() -> i32 {
    // Enabled (trapping) = mask bit clear. MXCSR mask bits 7-12.
    let masks = (read_mxcsr() >> MXCSR_MASK_SHIFT) as i32 & super::FE_ALL_EXCEPT;
    (!masks) & super::FE_ALL_EXCEPT
}

pub(super) fn enableexcept(excepts: i32) {
    let e = (excepts & super::FE_ALL_EXCEPT) as u32;
    write_mxcsr(read_mxcsr() & !(e << MXCSR_MASK_SHIFT));
    let ecw = (excepts & super::FE_ALL_EXCEPT) as u16;
    write_x87cw(read_x87cw() & !ecw);
}

pub(super) fn disableexcept(excepts: i32) {
    let e = (excepts & super::FE_ALL_EXCEPT) as u32;
    write_mxcsr(read_mxcsr() | (e << MXCSR_MASK_SHIFT));
    let ecw = (excepts & super::FE_ALL_EXCEPT) as u16;
    write_x87cw(read_x87cw() | ecw);
}

pub(super) fn getenv() -> fenv_t {
    // SAFETY: fenv_t is a plain-old-data fstenv block of integers with no
    // invalid bit patterns; zeroing it is sound and the fields are overwritten.
    let mut e: fenv_t = unsafe { core::mem::zeroed() };
    e.__control_word = read_x87cw();
    e.__status_word = read_x87sw();
    e.__mxcsr = read_mxcsr();
    e
}

pub(super) fn setenv(e: &fenv_t) {
    write_x87cw(e.__control_word);
    clear_x87_flags();
    write_mxcsr(e.__mxcsr);
}

pub(super) fn set_default_env() -> i32 {
    // glibc default: all exceptions masked, round-to-nearest, flags clear.
    // x87 control word default 0x037f (all masks set, round nearest, 64-bit).
    write_x87cw(0x037f);
    clear_x87_flags();
    // MXCSR default 0x1f80 (all 6 masks set, round nearest, FTZ/DAZ off).
    write_mxcsr(0x1f80);
    0
}

pub(super) fn getmode() -> femode_t {
    femode_t { __control_word: read_x87cw(), __reserved: 0, __mxcsr: read_mxcsr() }
}

pub(super) fn setmode(m: &femode_t) {
    // Control modes = rounding + trap-enable masks; preserve cumulative flags.
    write_x87cw(m.__control_word);
    let flags = read_mxcsr() & super::FE_ALL_EXCEPT as u32; // keep raised flags
    write_mxcsr((m.__mxcsr & !(super::FE_ALL_EXCEPT as u32)) | flags);
}

pub(super) fn set_default_mode() -> i32 {
    let flags = read_mxcsr() & super::FE_ALL_EXCEPT as u32;
    write_x87cw(0x037f);
    write_mxcsr(0x1f80 | flags);
    let _ = FE_TONEAREST;
    0
}
