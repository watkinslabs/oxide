use super::*;
extern crate alloc;
use self::alloc::vec::Vec;

const LINUX: [u64; 6] = [0xdead, 0xbeef, 0x7f65_0000_2222, 0x7f65_0000_1111, 0x7f65_0000_3333, 0x7f65_0000_4444];
const WINDOWS: [u64; 6] = [LINUX[3], LINUX[2], LINUX[4], LINUX[5], 0, 0];

#[test]
fn pfn_four_register_arguments_need_no_stack() {
    assert_eq!(decode_x64(0x147a, LINUX, |_| { assert!(false, "PFN read stack"); None }), Decoded::Ready(WINDOWS));
}

#[test]
fn installed_signature_counts_and_admission_are_exact() {
    // Captured x64 argument-table bytes for the existing claimed ordinals.
    let signatures = [
        (0x10a2,32), (0x10a7,40), (0x10ae,8), (0x10b9,24), (0x10ba,32), (0x10bb,32), (0x10bf,16), (0x118f,8), (0x11c7,24), (0x11c9,72), (0x11da,32), (0x11db,16), (0x11ef,24), (0x11f0,16), (0x121e,16), (0x1227,64), (0x1229,24), (0x1233,40), (0x1238,40), (0x123a,24), (0x1243,32), (0x1246,40), (0x124c,48), (0x1258,16), (0x1259,40), (0x126c,16), (0x126e,16), (0x126f,16),
        (0x1287,40), (0x1327,16), (0x1332,16), (0x1336,24), (0x133a,16), (0x133c,8), (0x133d,16), (0x133e,24), (0x1347,24), (0x1351,0), (0x135a,24), (0x135c,16),
        (0x1360,32), (0x1366,0), (0x1368,0), (0x136b,136), (0x1378,24), (0x137b,8), (0x137e,0), (0x1382,8),
        (0x1384,8), (0x138b,8), (0x139b,8), (0x139c,40), (0x13a7,24),
        (0x13bc,16), (0x13d0,8), (0x13d5,0), (0x13d6,8), (0x13d8,32), (0x13d9,24), (0x13eb,8), (0x13ec,24), (0x1410,8), (0x1414,8), (0x1418,32), (0x141a,32),
        (0x141b,32), (0x1435,8), (0x1438,16), (0x144b,8), (0x1463,16), (0x146c,8), (0x147a,32), (0x148c,24),
        (0x14b5,56), (0x14ba,48), (0x14c2,16), (0x14ca,40), (0x14d0,32), (0x14e9,32), (0x14eb,56),
        (0x1507,8), (0x1509,16), (0x151d,24), (0x151e,16), (0x1532,8), (0x153b,8), (0x153c,16), (0x1557,8), (0x1565,8),
        (0x1569,16), (0x1577,16), (0x157f,24), (0x1581,32), (0x15a3,32), (0x15a4,32), (0x15a6,16), (0x15a7,56), (0x15ad,24), (0x15b7,8), (0x15bd,16), (0x15cb,32), (0x15d0,48), (0x15d7,24), (0x15d8,16),
    ];
    assert_eq!(RAW_CALLS.len(), signatures.len());
    assert!(RAW_CALLS.windows(2).all(|pair| pair[0].0 < pair[1].0));
    for ordinal in 0..0x2000 {
        let fonts = [(0x11e6,6), (0x11fe,5), (0x1204,5), (0x1211,4), (0x1225,3)];
        assert_eq!(argument_count(ordinal), signatures.iter().find(|entry| entry.0 == ordinal).map(|entry| entry.1 / 8)
            .or_else(|| fonts.iter().find(|entry| entry.0 == ordinal).map(|entry| entry.1)));
    }
}

#[test]
fn every_signature_reads_only_its_first_six_parameters() {
    for &(ordinal, count) in RAW_CALLS {
        let mut reads = Vec::new();
        let result = decode_x64(ordinal, LINUX, |index| { reads.push(index); Some(0x7000 + index as u64) });
        let mut expected = WINDOWS;
        for index in 4..count.min(6) { expected[index] = 0x7000 + index as u64; }
        assert_eq!(result, Decoded::Ready(expected));
        assert_eq!(reads, (4..count.min(6)).collect::<Vec<_>>());
    }
}

#[test]
fn five_parameter_calls_do_not_probe_sixth_slot() {
    for ordinal in [0x139c, 0x14ca] {
        let mut expected = WINDOWS;
        expected[4] = u64::MAX;
        assert_eq!(decode_x64(ordinal, LINUX, |index| if index == 4 { Some(u64::MAX) } else { None }), Decoded::Ready(expected));
    }
}

#[test]
fn stack_fault_reports_index_and_stops_before_dispatch() {
    let mut reads = Vec::new();
    assert_eq!(decode_x64(0x136b, LINUX, |index| { reads.push(index); None }), Decoded::StackFault(4));
    assert_eq!(reads, [4]);
    reads.clear();
    assert_eq!(decode_x64(0x15d0, LINUX, |index| { reads.push(index); (index == 4).then_some(0x1234) }), Decoded::StackFault(5));
    assert_eq!(reads, [4, 5]);
}

#[test]
fn unclaimed_linux_and_tagged_calls_never_probe_or_convert() {
    for ordinal in [0, 1, 0x131b, 0x15df, 0x1604,
        0x4e54_0000_0000_147a, 0x4e54_0000_0000_0217, u64::MAX] {
        assert_eq!(decode_x64(ordinal, LINUX, |_| { assert!(false, "unclaimed call read stack"); None }), Decoded::Unclaimed);
    }
    assert_eq!(LINUX[0..2], [0xdead, 0xbeef]);
}
