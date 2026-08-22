use alloc::{vec, vec::Vec};
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

use super::{GIC_ITS_PA, GIC_MSI_FRAME_PA, RsdpStatus, decode_madt, try_log_rsdp};

static CPU_COUNT: AtomicUsize = AtomicUsize::new(0);
static CPU_ID: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];
static CPU_FLAGS: [AtomicU32; 3] = [const { AtomicU32::new(0) }; 3];
static CPU_UID: [AtomicU32; 3] = [const { AtomicU32::new(0) }; 3];

unsafe fn record_cpu(id: u64, flags: u32, uid: u32) -> bool {
    let index = CPU_COUNT.fetch_add(1, Ordering::AcqRel);
    if index >= CPU_ID.len() { return false; }
    CPU_ID[index].store(id, Ordering::Release);
    CPU_FLAGS[index].store(flags, Ordering::Release);
    CPU_UID[index].store(uid, Ordering::Release);
    true
}

fn append(table: &mut Vec<u8>, entry: &[u8]) { table.extend_from_slice(entry); }

#[test]
fn absent_returns_absent() {
    // SAFETY: rsdp_va=0 path returns immediately; pointer is never dereferenced.
    assert_eq!(unsafe { try_log_rsdp(0) }, RsdpStatus::Absent);
}

#[test]
fn rsdp_status_distinct() {
    assert_ne!(RsdpStatus::Absent, RsdpStatus::BadSignature);
    assert_ne!(RsdpStatus::Logged, RsdpStatus::BadSignature);
}

#[test]
fn madt_entry_offsets_reach_the_published_platform_owners() {
    let mut table = vec![0u8; 44];
    append(&mut table, &[0, 8, 0x31, 0x42, 0x03, 0, 0, 0]);
    append(&mut table, &[9, 16, 0, 0, 0x78, 0x56, 0x34, 0x12,
        0x05, 0, 0, 0, 0xef, 0xcd, 0xab, 0x90]);
    let mut gicc = [0u8; 80];
    gicc[0] = 11;
    gicc[1] = 80;
    gicc[4..8].copy_from_slice(&0x3141_5926u32.to_le_bytes());
    gicc[8..12].copy_from_slice(&0x5358_9793u32.to_le_bytes());
    gicc[12..16].copy_from_slice(&0x0000_0003u32.to_le_bytes());
    gicc[68..76].copy_from_slice(&0x0123_4567_89ab_cdefu64.to_le_bytes());
    append(&mut table, &gicc);
    append(&mut table, &[1, 12, 0x5a, 0, 0, 0, 0xc0, 0xfe, 0x20, 0, 0, 0]);
    append(&mut table, &[2, 10, 0, 7, 0x2b, 0, 0, 0, 0x0f, 0]);
    append(&mut table, &[13, 24, 0, 0, 0x44, 0x33, 0x22, 0x11,
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
        0x03, 0, 0, 0, 0, 0, 0, 0]);
    append(&mut table, &[15, 20, 0, 0, 0xdd, 0xcc, 0xbb, 0xaa,
        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0, 0, 0, 0]);
    let table_len = table.len() as u32;
    table[4..8].copy_from_slice(&table_len.to_le_bytes());
    table[36..40].copy_from_slice(&0xfee0_0000u32.to_le_bytes());

    CPU_COUNT.store(0, Ordering::Release);
    crate::set_add_cpu_hook(record_cpu);
    // SAFETY: the owned byte vector contains a complete MADT with a declared
    // length equal to its allocation, and a zero HHDM offset addresses it directly.
    unsafe { decode_madt(table.as_ptr() as u64, 0); }

    assert_eq!(CPU_COUNT.load(Ordering::Acquire), 3);
    assert_eq!((CPU_ID[0].load(Ordering::Acquire), CPU_FLAGS[0].load(Ordering::Acquire), CPU_UID[0].load(Ordering::Acquire)),
        (0x42, 0x03, 0x31));
    assert_eq!((CPU_ID[1].load(Ordering::Acquire), CPU_FLAGS[1].load(Ordering::Acquire), CPU_UID[1].load(Ordering::Acquire)),
        (0x1234_5678, 0x05, 0x90ab_cdef));
    assert_eq!((CPU_ID[2].load(Ordering::Acquire), CPU_FLAGS[2].load(Ordering::Acquire), CPU_UID[2].load(Ordering::Acquire)),
        (0x0123_4567_89ab_cdef, 0x03, 0x5358_9793));
    assert_eq!(crate::ioapic(0), Some(crate::IoApic { id: 0x5a, pa: 0xfec0_0000, gsi_base: 0x20 }));
    assert_eq!(crate::legacy_irq_gsi(7), Some(0x2b));
    assert_eq!(crate::legacy_irq_flags(7), Some(0x0f));
    assert_eq!(GIC_MSI_FRAME_PA.load(Ordering::Acquire), 0x1122_3344_5566_7788);
    assert_eq!(GIC_ITS_PA.load(Ordering::Acquire), 0xfedc_ba98_7654_3210);
}
