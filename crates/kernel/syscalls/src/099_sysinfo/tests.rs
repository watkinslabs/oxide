// sysinfo(2) ABI tests: exact `struct sysinfo` geometry, the SI_LOAD_SHIFT
// rescale (the detail most often left at the scheduler's FSHIFT), and the
// uptime round-up.

use super::*;

fn u64_at(img: &[u8; SYSINFO_BYTES], off: usize) -> u64 {
    u64::from_le_bytes(img[off..off + 8].try_into().unwrap())
}

fn sample() -> SysInfo {
    SysInfo {
        uptime_sec: 1234,
        loads: [0x1111, 0x2222, 0x3333],
        totalram:  0x4000_0000,
        freeram:   0x1000_0000,
        sharedram: 0x0020_0000,
        bufferram: 0x0030_0000,
        totalswap: 0x0800_0000,
        freeswap:  0x0700_0000,
        procs: 137,
        totalhigh: 0,
        freehigh: 0,
    }
}

#[test]
fn struct_sysinfo_is_112_bytes_on_both_lp64_arches() {
    // 1 long + 3 ulong + 6 ulong + 2×u16 + 2 ulong + u32 + _f[4] = 112.
    // x86_64 and aarch64 share the generic LP64 definition, so ONE encoder
    // serves both.
    assert_eq!(SYSINFO_BYTES, 112);
    assert_eq!(encode_sysinfo(&sample()).len(), 112);
}

#[test]
fn offsets_are_the_linux_uapi_values() {
    assert_eq!((OFF_UPTIME, OFF_LOADS, OFF_TOTALRAM, OFF_FREERAM), (0, 8, 32, 40));
    assert_eq!((OFF_SHAREDRAM, OFF_BUFFERRAM, OFF_TOTALSWAP, OFF_FREESWAP), (48, 56, 64, 72));
    assert_eq!((OFF_PROCS, OFF_PAD, OFF_TOTALHIGH, OFF_FREEHIGH), (80, 82, 88, 96));
    assert_eq!((OFF_MEM_UNIT, OFF_F), (104, 108));
}

#[test]
fn every_field_lands_at_its_linux_offset() {
    let s = sample();
    let b = encode_sysinfo(&s);
    assert_eq!(u64_at(&b, OFF_UPTIME), 1234);
    assert_eq!(u64_at(&b, OFF_LOADS), 0x1111);
    assert_eq!(u64_at(&b, OFF_LOADS + 8), 0x2222);
    assert_eq!(u64_at(&b, OFF_LOADS + 16), 0x3333);
    assert_eq!(u64_at(&b, OFF_TOTALRAM), s.totalram);
    assert_eq!(u64_at(&b, OFF_FREERAM), s.freeram);
    assert_eq!(u64_at(&b, OFF_SHAREDRAM), s.sharedram);
    assert_eq!(u64_at(&b, OFF_BUFFERRAM), s.bufferram);
    assert_eq!(u64_at(&b, OFF_TOTALSWAP), s.totalswap);
    assert_eq!(u64_at(&b, OFF_FREESWAP), s.freeswap);
    assert_eq!(u16::from_le_bytes(b[OFF_PROCS..OFF_PROCS + 2].try_into().unwrap()), 137);
    assert_eq!(u32::from_le_bytes(b[OFF_MEM_UNIT..OFF_MEM_UNIT + 4].try_into().unwrap()), 1);
}

#[test]
fn procs_is_a_u16_and_does_not_bleed_into_the_pad() {
    let b = encode_sysinfo(&SysInfo { procs: u16::MAX, ..SysInfo::default() });
    assert_eq!(&b[OFF_PROCS..OFF_PROCS + 2], &[0xff, 0xff]);
    // `__u16 pad` and the 4 bytes before totalhigh stay zero.
    assert!(b[OFF_PAD..OFF_TOTALHIGH].iter().all(|&x| x == 0));
}

#[test]
fn the_libc5_padding_tail_is_zero() {
    let b = encode_sysinfo(&sample());
    assert!(b[OFF_F..].iter().all(|&x| x == 0), "_f[] must be zeroed");
    assert_eq!(SYSINFO_BYTES - OFF_F, 4);
}

#[test]
fn mem_unit_is_one_because_the_fields_are_already_bytes() {
    // `do_sysinfo` gathers in PAGES with mem_unit = PAGE_SIZE, then — when the
    // page→byte shift does not overflow, which it never does on LP64 —
    // multiplies every memory field out and sets mem_unit to 1. Reporting
    // mem_unit = 1 alongside byte-valued fields is that same final state.
    assert_eq!(MEM_UNIT_BYTES, 1);
    let b = encode_sysinfo(&sample());
    assert_eq!(u32::from_le_bytes(b[OFF_MEM_UNIT..OFF_MEM_UNIT + 4].try_into().unwrap()), 1);
}

#[test]
fn loads_use_si_load_shift_not_the_scheduler_fshift() {
    // The scheduler keeps averages at FSHIFT = 11; the sysinfo ABI carries
    // SI_LOAD_SHIFT = 16. Shipping the raw FSHIFT value understates every load
    // average by a factor of 32.
    assert_eq!(SI_LOAD_SHIFT, 16);
    const FSHIFT: u32 = 11;
    let one_fshift = 1u64 << FSHIFT;           // 1.00 at the scheduler's scale
    assert_eq!(load_to_si(one_fshift, FSHIFT), 1u64 << SI_LOAD_SHIFT);
    assert_eq!(load_to_si(one_fshift, FSHIFT), one_fshift * 32);
    assert_eq!(load_to_si(0, FSHIFT), 0);
    // A load of 2.50 round-trips to 2.5 << 16.
    let two_and_a_half = one_fshift * 5 / 2;
    assert_eq!(load_to_si(two_and_a_half, FSHIFT), (1u64 << SI_LOAD_SHIFT) * 5 / 2);
}

#[test]
fn uptime_rounds_up_on_any_sub_second_remainder() {
    // Linux: `tp.tv_sec + (tp.tv_nsec ? 1 : 0)`.
    assert_eq!(uptime_secs(0), 0);
    assert_eq!(uptime_secs(1), 1, "any remainder rounds the second up");
    assert_eq!(uptime_secs(999_999_999), 1);
    assert_eq!(uptime_secs(1_000_000_000), 1, "an exact second does not round up");
    assert_eq!(uptime_secs(1_000_000_001), 2);
    assert_eq!(uptime_secs(90_500_000_000), 91);
}

#[test]
fn totalhigh_and_freehigh_are_zero_on_a_64_bit_kernel() {
    // `si_meminfo` fills these from `totalhigh_pages()`/`nr_free_highpages()`,
    // which are 0 without CONFIG_HIGHMEM — a 64-bit kernel has no high memory.
    // These zeros are the Linux answer, not an unfilled field.
    let b = encode_sysinfo(&sample());
    assert_eq!(u64_at(&b, OFF_TOTALHIGH), 0);
    assert_eq!(u64_at(&b, OFF_FREEHIGH), 0);
}
