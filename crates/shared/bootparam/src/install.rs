// Live boot-console state and the klog sink that drives it.
//
// klog sinks are plain `fn(&[u8])` (no `dyn`, `07§5`), so the resolved
// request lives in atomics that the sink reads on each call. Boot is the sole
// writer and it writes before registering the sink, so no reader can observe
// a half-installed port.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use cmdline::{Driver, EarlyconSpec, IoType};

use crate::access::Access;

static INSTALLED: AtomicBool = AtomicBool::new(false);
/// Already-translated base: a port number, or a kernel VA for the MMIO forms.
static BASE: AtomicU64 = AtomicU64::new(0);
static IOTYPE: AtomicU32 = AtomicU32::new(0);
static DRIVER: AtomicU32 = AtomicU32::new(0);
static BAUD: AtomicU32 = AtomicU32::new(0);

const IO_PORT: u32 = 0;
const IO_MEM: u32 = 1;
const IO_MEM16: u32 = 2;
const IO_MEM32: u32 = 3;
const IO_MEM32BE: u32 = 4;
const DRV_8250: u32 = 0;
const DRV_PL011: u32 = 1;

fn encode_io(io: IoType) -> u32 {
    match io { IoType::Port => IO_PORT, IoType::Mem => IO_MEM, IoType::Mem16 => IO_MEM16, IoType::Mem32 => IO_MEM32, IoType::Mem32Be => IO_MEM32BE }
}

fn decode_io(v: u32) -> IoType {
    match v { IO_PORT => IoType::Port, IO_MEM => IoType::Mem, IO_MEM16 => IoType::Mem16, IO_MEM32BE => IoType::Mem32Be, _ => IoType::Mem32 }
}

/// Is a boot console live? # C: O(1)
pub fn installed() -> bool { INSTALLED.load(Ordering::Acquire) }

/// The resolved request, or `None` before one is installed. # C: O(1)
pub fn spec() -> Option<EarlyconSpec> {
    if !installed() { return None; }
    Some(EarlyconSpec {
        driver: if DRIVER.load(Ordering::Acquire) == DRV_PL011 { Driver::Pl011 } else { Driver::Uart8250 },
        iotype: decode_io(IOTYPE.load(Ordering::Acquire)),
        addr: BASE.load(Ordering::Acquire),
        baud: BAUD.load(Ordering::Acquire),
    })
}

/// Translate a spec's address for the running kernel and decide the base the
/// accessor binds to. Port I/O addresses are ports; memory addresses are
/// physical and reach the kernel through the direct map. Split out global-free
/// so the translation is checkable without a live mapping.
/// # C: O(1)
pub fn base_for(spec: &EarlyconSpec, direct_map_offset: u64) -> u64 {
    match spec.iotype { IoType::Port => spec.addr, _ => spec.addr.wrapping_add(direct_map_offset) }
}

/// Program the UART `spec` names and register it as the boot console.
/// `direct_map_offset` is the kernel's direct-map base, applied to the MMIO
/// forms; pass 0 when physical addresses are already reachable.
///
/// Returns false without touching hardware when the request names no address,
/// so a malformed parameter cannot make the kernel drive an arbitrary port.
///
/// # SAFETY: caller is the boot path with a single CPU, and `spec.addr` must
/// name a real UART of the stated kind that no other code is driving.
/// # C: O(1)
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn install(spec: EarlyconSpec, direct_map_offset: u64) -> bool {
    if klog::warn::warn_on(spec.addr == 0, "earlycon request names no address; no boot console") { return false; }
    let base = base_for(&spec, direct_map_offset);
    BASE.store(base, Ordering::Release);
    IOTYPE.store(encode_io(spec.iotype), Ordering::Release);
    DRIVER.store(if spec.driver == Driver::Pl011 { DRV_PL011 } else { DRV_8250 }, Ordering::Release);
    BAUD.store(spec.baud, Ordering::Release);
    if spec.driver == Driver::Uart8250 {
        crate::uart8250::init(&Access::new(spec.iotype, base as usize), spec.baud);
    }
    INSTALLED.store(true, Ordering::Release);
    klog::set_boot_console(emit);
    true
}

/// klog sink for the boot console. Writes each byte straight to the UART,
/// expanding a newline to CR+LF the way a terminal expects.
/// # C: O(bytes.len())
pub fn emit(bytes: &[u8]) {
    if !installed() { return; }
    let io = decode_io(IOTYPE.load(Ordering::Acquire));
    let a = Access::new(io, BASE.load(Ordering::Acquire) as usize);
    let pl011 = DRIVER.load(Ordering::Acquire) == DRV_PL011;
    for &b in bytes {
        if b == b'\n' { putc(&a, pl011, b'\r'); }
        putc(&a, pl011, b);
    }
}

#[inline]
fn putc(a: &Access, pl011: bool, b: u8) {
    if pl011 { crate::pl011::putc(a, b) } else { crate::uart8250::putc(a, b) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec_of(io: IoType, addr: u64) -> EarlyconSpec {
        EarlyconSpec { driver: Driver::Uart8250, iotype: io, addr, baud: 115_200 }
    }

    #[test]
    fn port_addresses_are_not_direct_mapped() {
        assert_eq!(base_for(&spec_of(IoType::Port, 0x3f8), 0xffff_8000_0000_0000), 0x3f8);
    }

    #[test]
    fn memory_addresses_go_through_the_direct_map() {
        let off = 0xffff_8000_0000_0000u64;
        assert_eq!(base_for(&spec_of(IoType::Mem32, 0x0900_0000), off), off + 0x0900_0000);
        assert_eq!(base_for(&spec_of(IoType::Mem, 0x0900_0000), 0), 0x0900_0000);
    }

    #[test]
    fn io_type_round_trips_through_the_atomic_encoding() {
        for io in [IoType::Port, IoType::Mem, IoType::Mem16, IoType::Mem32, IoType::Mem32Be] {
            assert_eq!(decode_io(encode_io(io)), io);
        }
    }

    #[test]
    fn an_address_less_request_installs_nothing() {
        // SAFETY: hosted test; the guarded path returns before any register access.
        assert!(!unsafe { install(spec_of(IoType::Mem32, 0), 0) }, "a request with no address must not drive a port");
        assert!(!installed());
        assert_eq!(spec(), None);
    }
}
