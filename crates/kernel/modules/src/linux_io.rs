// Linux MMIO and port-I/O KPI exports for loadable drivers.

extern crate alloc;

use alloc::vec::Vec;
use core::ffi::c_void;
use core::ptr::{copy_nonoverlapping, read_volatile, write_volatile};
use core::sync::atomic::{compiler_fence, fence, Ordering};
use sync::{Modules as ModulesLockClass, Spinlock};

const PAGE_SHIFT: u64 = 12;
const PAGE_SIZE: u64 = 1u64 << PAGE_SHIFT;
const PAGE_MASK: u64 = !(PAGE_SIZE - 1);

#[derive(Copy, Clone)]
struct IoMapping {
    user_va: usize,
    base_va: u64,
    n_pages: u64,
}

static IOREMAPS: Spinlock<Vec<IoMapping>, ModulesLockClass> = Spinlock::new(Vec::new());

/// Register Linux MMIO and port-I/O KPI symbols.
/// # C: O(1)
pub fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("ioremap",        ioremap        as *const () as usize),
        ("ioremap_nocache", ioremap       as *const () as usize),
        ("iounmap",        iounmap        as *const () as usize),
        ("readb",          readb          as *const () as usize),
        ("readw",          readw          as *const () as usize),
        ("readl",          readl          as *const () as usize),
        ("readq",          readq          as *const () as usize),
        ("writeb",         writeb         as *const () as usize),
        ("writew",         writew         as *const () as usize),
        ("writel",         writel         as *const () as usize),
        ("writeq",         writeq         as *const () as usize),
        ("memcpy_toio",    memcpy_toio    as *const () as usize),
        ("memcpy_fromio",  memcpy_fromio  as *const () as usize),
        ("memset_io",      memset_io      as *const () as usize),
        ("inb",            inb            as *const () as usize),
        ("inw",            inw            as *const () as usize),
        ("inl",            inl            as *const () as usize),
        ("outb",           outb           as *const () as usize),
        ("outw",           outw           as *const () as usize),
        ("outl",           outl           as *const () as usize),
        ("mb",             mb             as *const () as usize),
        ("rmb",            rmb            as *const () as usize),
        ("wmb",            wmb            as *const () as usize),
        ("mmiowb",         mmiowb         as *const () as usize),
    ] { export(name, addr, false); }
}

extern "C" fn ioremap(phys: u64, size: usize) -> *mut c_void {
    if size == 0 { return core::ptr::null_mut(); }
    let off = phys & (PAGE_SIZE - 1);
    let base = phys & PAGE_MASK;
    let total = match off.checked_add(size as u64) { Some(v) => v, None => return core::ptr::null_mut() };
    let n_pages = pages_for(total);
    let base_va = map_mmio(base, n_pages);
    if base_va == 0 { return core::ptr::null_mut(); }
    let user_va = (base_va + off) as usize;
    IOREMAPS.lock().push(IoMapping { user_va, base_va, n_pages });
    user_va as *mut c_void
}

extern "C" fn iounmap(addr: *mut c_void) {
    if addr.is_null() { return; }
    let user_va = addr as usize;
    let rec = {
        let mut g = IOREMAPS.lock();
        match g.iter().position(|m| m.user_va == user_va) {
            Some(i) => Some(g.swap_remove(i)),
            None => None,
        }
    };
    if let Some(m) = rec { unmap_mmio(m.base_va, m.n_pages); }
}

unsafe extern "C" fn readb(addr: *const c_void) -> u8 {
    // SAFETY: Linux caller supplies a valid byte MMIO register pointer.
    unsafe { io_load(addr as *const u8) }
}
unsafe extern "C" fn readw(addr: *const c_void) -> u16 {
    // SAFETY: Linux caller supplies a valid halfword MMIO register pointer.
    unsafe { io_load(addr as *const u16) }
}
unsafe extern "C" fn readl(addr: *const c_void) -> u32 {
    // SAFETY: Linux caller supplies a valid word MMIO register pointer.
    unsafe { io_load(addr as *const u32) }
}
unsafe extern "C" fn readq(addr: *const c_void) -> u64 {
    // SAFETY: Linux caller supplies a valid doubleword MMIO register pointer.
    unsafe { io_load(addr as *const u64) }
}
unsafe extern "C" fn writeb(v: u8, addr: *mut c_void) {
    // SAFETY: Linux caller supplies a valid byte MMIO register pointer.
    unsafe { io_store(addr as *mut u8, v); }
}
unsafe extern "C" fn writew(v: u16, addr: *mut c_void) {
    // SAFETY: Linux caller supplies a valid halfword MMIO register pointer.
    unsafe { io_store(addr as *mut u16, v); }
}
unsafe extern "C" fn writel(v: u32, addr: *mut c_void) {
    // SAFETY: Linux caller supplies a valid word MMIO register pointer.
    unsafe { io_store(addr as *mut u32, v); }
}
unsafe extern "C" fn writeq(v: u64, addr: *mut c_void) {
    // SAFETY: Linux caller supplies a valid doubleword MMIO register pointer.
    unsafe { io_store(addr as *mut u64, v); }
}

unsafe extern "C" fn memcpy_toio(dst: *mut c_void, src: *const c_void, n: usize) {
    if dst.is_null() || src.is_null() { return; }
    // SAFETY: Linux caller provides non-overlapping buffers spanning n bytes.
    unsafe { copy_nonoverlapping(src as *const u8, dst as *mut u8, n); }
    wmb();
}

unsafe extern "C" fn memcpy_fromio(dst: *mut c_void, src: *const c_void, n: usize) {
    if dst.is_null() || src.is_null() { return; }
    rmb();
    // SAFETY: Linux caller provides non-overlapping buffers spanning n bytes.
    unsafe { copy_nonoverlapping(src as *const u8, dst as *mut u8, n); }
}

unsafe extern "C" fn memset_io(dst: *mut c_void, v: i32, n: usize) {
    if dst.is_null() { return; }
    for i in 0..n {
        // SAFETY: Linux caller provides an MMIO window spanning n bytes.
        unsafe { write_volatile((dst as *mut u8).add(i), v as u8); }
    }
    wmb();
}

extern "C" fn mb() { arch_mmio_barrier(); }
extern "C" fn rmb() { fence(Ordering::SeqCst); }
extern "C" fn wmb() { arch_mmio_barrier(); }
extern "C" fn mmiowb() { arch_mmio_barrier(); }

unsafe fn io_load<T: Copy>(addr: *const T) -> T {
    rmb();
    // SAFETY: caller supplies a valid volatile device register pointer.
    let v = unsafe { read_volatile(addr) };
    compiler_fence(Ordering::SeqCst);
    v
}

unsafe fn io_store<T: Copy>(addr: *mut T, v: T) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller supplies a valid volatile device register pointer.
    unsafe { write_volatile(addr, v); }
    wmb();
}

fn pages_for(bytes: u64) -> u64 {
    (bytes + PAGE_SIZE - 1) >> PAGE_SHIFT
}

#[cfg(target_os = "oxide-kernel")]
fn map_mmio(pa: u64, n_pages: u64) -> u64 {
    // SAFETY: exported ioremap is called by trusted kernel modules for owned device MMIO.
    unsafe { mmio_map::map_pages(pa, n_pages) }
}

#[cfg(not(target_os = "oxide-kernel"))]
fn map_mmio(pa: u64, _n_pages: u64) -> u64 { pa }

#[cfg(target_os = "oxide-kernel")]
fn unmap_mmio(base_va: u64, n_pages: u64) {
    // SAFETY: IOREMAPS owns the VA range removed before this call.
    unsafe { mmio_map::unmap_pages(base_va, n_pages); }
}

#[cfg(not(target_os = "oxide-kernel"))]
fn unmap_mmio(_base_va: u64, _n_pages: u64) {}

#[cfg(target_arch = "x86_64")]
extern "C" fn inb(port: u16) -> u8 {
    let v: u8;
    // SAFETY: x86 IN reads the caller-selected I/O port in kernel context.
    unsafe { core::arch::asm!("in al, dx", in("dx") port, out("al") v, options(nomem, nostack, preserves_flags)); }
    v
}

#[cfg(not(target_arch = "x86_64"))]
extern "C" fn inb(_port: u16) -> u8 { 0 }

#[cfg(target_arch = "x86_64")]
extern "C" fn inw(port: u16) -> u16 {
    let v: u16;
    // SAFETY: x86 IN reads the caller-selected I/O port in kernel context.
    unsafe { core::arch::asm!("in ax, dx", in("dx") port, out("ax") v, options(nomem, nostack, preserves_flags)); }
    v
}

#[cfg(not(target_arch = "x86_64"))]
extern "C" fn inw(_port: u16) -> u16 { 0 }

#[cfg(target_arch = "x86_64")]
extern "C" fn inl(port: u16) -> u32 {
    let v: u32;
    // SAFETY: x86 IN reads the caller-selected I/O port in kernel context.
    unsafe { core::arch::asm!("in eax, dx", in("dx") port, out("eax") v, options(nomem, nostack, preserves_flags)); }
    v
}

#[cfg(not(target_arch = "x86_64"))]
extern "C" fn inl(_port: u16) -> u32 { 0 }

#[cfg(target_arch = "x86_64")]
extern "C" fn outb(v: u8, port: u16) {
    // SAFETY: x86 OUT writes the caller-selected I/O port in kernel context.
    unsafe { core::arch::asm!("out dx, al", in("dx") port, in("al") v, options(nomem, nostack, preserves_flags)); }
}

#[cfg(not(target_arch = "x86_64"))]
extern "C" fn outb(_v: u8, _port: u16) {}

#[cfg(target_arch = "x86_64")]
extern "C" fn outw(v: u16, port: u16) {
    // SAFETY: x86 OUT writes the caller-selected I/O port in kernel context.
    unsafe { core::arch::asm!("out dx, ax", in("dx") port, in("ax") v, options(nomem, nostack, preserves_flags)); }
}

#[cfg(not(target_arch = "x86_64"))]
extern "C" fn outw(_v: u16, _port: u16) {}

#[cfg(target_arch = "x86_64")]
extern "C" fn outl(v: u32, port: u16) {
    // SAFETY: x86 OUT writes the caller-selected I/O port in kernel context.
    unsafe { core::arch::asm!("out dx, eax", in("dx") port, in("eax") v, options(nomem, nostack, preserves_flags)); }
}

#[cfg(not(target_arch = "x86_64"))]
extern "C" fn outl(_v: u32, _port: u16) {}

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
fn arch_mmio_barrier() { hal_x86_64::mmio_barrier(); }

#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
fn arch_mmio_barrier() { hal_aarch64::mmio_barrier(); }

#[cfg(not(target_os = "oxide-kernel"))]
fn arch_mmio_barrier() { fence(Ordering::SeqCst); }

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_QWORD: u64 = 0x1122_3344_5566_7788;
    const TEST_BYTE: u8 = 0xaa;
    const TEST_OFFSET: u64 = 3;
    const TEST_LEN: usize = 8;

    #[test]
    fn volatile_accessors_round_trip_on_host_memory() {
        let _modules = crate::test_serial::claim();
        let mut q = 0u64;
        let p = &mut q as *mut u64 as *mut c_void;
        // SAFETY: p is the address of the u64 `q` on this test's stack, so it is writable and
        // 8-byte aligned — enough for the widest access here (writeq/readq); the narrower
        // writeb/readb touch its first byte. No real MMIO window is involved.
        unsafe {
            writeq(TEST_QWORD, p);
            assert_eq!(readq(p), TEST_QWORD);
            writeb(TEST_BYTE, p);
            assert_eq!(readb(p), TEST_BYTE);
        }
    }

    #[test]
    fn hosted_ioremap_preserves_offset_and_unmaps() {
        let _modules = crate::test_serial::claim();
        let mut bytes = [0u8; PAGE_SIZE as usize];
        let phys = bytes.as_mut_ptr() as u64 + TEST_OFFSET;
        let p = ioremap(phys, TEST_LEN);
        assert_eq!(p as usize, phys as usize);
        assert_eq!(IOREMAPS.lock().len(), 1);
        iounmap(p);
        assert_eq!(IOREMAPS.lock().len(), 0);
    }

    #[test]
    fn export_symbols_registers_io_surface() {
        let _modules = crate::test_serial::claim();
        export_symbols();
        for name in [
            "ioremap", "ioremap_nocache", "iounmap", "readb", "readw", "readl", "readq",
            "writeb", "writew", "writel", "writeq", "memcpy_toio", "memcpy_fromio",
            "memset_io", "inb", "inw", "inl", "outb", "outw", "outl", "mb", "rmb", "wmb",
            "mmiowb",
        ] {
            assert!(crate::symtab::resolve(name, true).is_ok(), "{name}");
        }
    }
}
