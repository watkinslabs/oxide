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
        (0x10a2,32), (0x10a7,40), (0x10ae,8), (0x10b9,24), (0x10ba,32), (0x10bb,32), (0x10bf,16), (0x118f,8), (0x11c7,24), (0x11c9,72), (0x11da,32), (0x11db,16), (0x11ef,24), (0x11f0,16), (0x11f4,16), (0x121e,16), (0x1227,64), (0x1229,24), (0x1233,40), (0x1238,40), (0x123a,24), (0x1243,32), (0x1246,40), (0x124c,48), (0x1258,16), (0x1259,40), (0x126c,16), (0x126e,16), (0x126f,16),
        (0x1287,40), (0x1321,24), (0x1327,16), (0x132c,32), (0x1332,16), (0x1336,24), (0x133a,16), (0x133c,8), (0x133d,16), (0x133e,24), (0x1347,24), (0x1351,0), (0x135a,24), (0x135c,16),
        (0x1360,32), (0x1364,8), (0x1366,0), (0x1368,0), (0x136b,136), (0x1378,24), (0x137b,8), (0x137e,0), (0x1381,8), (0x1382,8),
        (0x1384,8), (0x1389,8), (0x138b,8), (0x139b,8), (0x139c,40), (0x13a7,24),
        (0x13bc,16), (0x13d0,8), (0x13d5,0), (0x13d6,8), (0x13d8,32), (0x13d9,24), (0x13e7,0), (0x13eb,8), (0x13ec,24), (0x1410,8), (0x1414,8), (0x1418,32), (0x141a,32),
        (0x141b,32), (0x1435,8), (0x1438,16), (0x144b,8), (0x1463,16), (0x146c,8), (0x147a,32), (0x148c,24),
        (0x14b5,56), (0x14ba,48), (0x14be,16), (0x14c2,16), (0x14ca,40), (0x14d0,32), (0x14dd,16), (0x14df,16), (0x14e9,32), (0x14eb,56),
        (0x1507,8), (0x1509,16), (0x151d,24), (0x151e,16), (0x1532,8), (0x153b,8), (0x153c,16), (0x153e,32), (0x153f,32), (0x1540,24), (0x1546,8), (0x1557,8), (0x1565,8),
        (0x1569,16), (0x1577,16), (0x157f,24), (0x1581,32), (0x15a3,32), (0x15a4,32), (0x15a6,16), (0x15a7,56), (0x15ad,24), (0x15b7,8), (0x15bd,16), (0x15cb,32), (0x15d0,48), (0x15d7,24), (0x15d8,16), (0x15e5,24),
        // Cursor, capture, keyboard-layout and raw-input family.
        (0x1319,16), (0x1322,24), (0x1350,8), (0x137f,16), (0x13a9,8), (0x13aa,0), (0x13c5,24), (0x13da,8), (0x13e6,8), (0x13e8,32), (0x13e9,8), (0x13ea,8), (0x13f5,0), (0x1403,48), (0x1404,32), (0x140f,24), (0x1411,8), (0x1412,16), (0x1413,8), (0x141f,40), (0x143b,8), (0x143d,24), (0x143e,40), (0x143f,32), (0x1440,24), (0x1442,24), (0x144e,8), (0x1488,16), (0x1490,0), (0x14b1,24), (0x14f3,32), (0x14fa,24), (0x1503,8), (0x1508,0), (0x152e,24), (0x153a,8), (0x1548,32), (0x154a,16), (0x15b8,8), (0x15d1,56), (0x15d3,8), (0x15e0,16), (0x15f4,16),
    ];
    assert_eq!(RAW_CALLS.len(), signatures.len());
    assert!(RAW_CALLS.windows(2).all(|pair| pair[0].0 < pair[1].0));
    // Families that own their own signature table still reach admission
    // through this one function, so their byte counts are checked here too.
    let families = [
        (0x1084,8), (0x108d,48), (0x108f,80), (0x109b,8), (0x10a4,8), (0x10aa,8), (0x10b5,8),
        (0x118c,8), (0x1190,32), (0x1199,40), (0x119b,8), (0x119d,8), (0x11c3,88), (0x11c5,64),
        (0x11d5,0), (0x11e0,24), (0x11eb,16), (0x11f6,16), (0x1209,16), (0x1220,32), (0x122a,24),
        (0x1237,0), (0x1241,24), (0x124f,32), (0x1251,40), (0x125d,40), (0x125f,16), (0x1260,56),
        (0x1266,8), (0x1269,48), (0x126a,48), (0x1273,24), (0x1276,16), (0x1279,16), (0x127d,24),
        (0x1281,24), (0x1285,16), (0x128c,40), (0x128d,32), (0x128e,8), (0x1293,8), (0x1294,40),
    ];
    assert!(families.windows(2).all(|pair| pair[0].0 < pair[1].0));
    for ordinal in 0..0x2000 {
        let fonts = [(0x11e6,6), (0x11fe,5), (0x1204,5), (0x1211,4), (0x1225,3)];
        // Paths, region shapes and region clipping admit their own signatures.
        let shapes = [(0x1085,1), (0x1096,1), (0x10a0,1), (0x10b2,4), (0x10bc,6), (0x119e,1), (0x11c0,2),
            (0x11c2,5), (0x11c4,3), (0x11c8,3), (0x11d2,1), (0x11d3,3), (0x11d4,1), (0x11d8,5), (0x1212,4),
            (0x121a,3), (0x121d,3), (0x1239,2), (0x1244,3), (0x1245,3), (0x124d,1), (0x1253,3), (0x1254,3),
            (0x1257,2), (0x126d,2), (0x1280,1), (0x1291,1), (0x1292,1), (0x129d,1)];
        let bitmaps = crate::nt_gdi_bitmap_shape::ORDINALS;
        assert_eq!(argument_count(ordinal), signatures.iter().chain(families.iter())
            .find(|entry| entry.0 == ordinal).map(|entry| entry.1 / 8)
            .or_else(|| fonts.iter().find(|entry| entry.0 == ordinal).map(|entry| entry.1))
            .or_else(|| shapes.iter().find(|entry| entry.0 == ordinal).map(|entry| entry.1))
            .or_else(|| bitmaps.iter().find(|entry| entry.0 == ordinal).map(|entry| entry.1))
        );

        // The bitmap, blit and palette family keeps its own admission table.
        let bitmaps = crate::nt_gdi_bitmap_shape::ORDINALS;

            .or_else(|| shapes.iter().find(|entry| entry.0 == ordinal).map(|entry| entry.1)));
        assert_eq!(argument_count(ordinal), signatures.iter().find(|entry| entry.0 == ordinal).map(|entry| entry.1 / 8)
            .or_else(|| crate::nt_wine_font_family_contract::argument_count(ordinal)));

            .or_else(|| crate::nt_wine_font_family_contract::argument_count(ordinal))
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
