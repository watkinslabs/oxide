use super::*;

#[test]
fn validate_blk_size_clamps() {
    assert_eq!(blk::validate_blk_size(512), 512);
    assert_eq!(blk::validate_blk_size(4096), 4096);
    assert_eq!(blk::validate_blk_size(1024), 1024);
    assert_eq!(blk::validate_blk_size(0), 512);
    assert_eq!(blk::validate_blk_size(100), 512);
    assert_eq!(blk::validate_blk_size(511), 512);
    assert_eq!(blk::validate_blk_size(1000), 512);
    assert_eq!(blk::validate_blk_size(513), 512);
}

#[test]
fn capacity_blocks_4096() {
    assert_eq!(blk::capacity_blocks(2048, 4096), 256);
    assert_eq!(blk::capacity_blocks(2048, 512), 2048);
    assert_eq!(blk::capacity_blocks(2049, 4096), 256);
    assert_eq!(blk::capacity_blocks(0, 4096), 0);
    assert_eq!(blk::capacity_blocks(100, 0), 0);
}

#[test]
fn trim_serial_edges() {
    let mut out = [0u8; 20];
    let mut s = [0u8; 20];
    s[..10].copy_from_slice(b"oxide-root");
    let n = blk::trim_serial(&s, &mut out);
    assert_eq!(&out[..n], b"oxide-root");

    let full = [b'a'; 20];
    let mut o2 = [0u8; 20];
    let n2 = blk::trim_serial(&full, &mut o2);
    assert_eq!(n2, 20);
    assert_eq!(&o2[..n2], &full[..]);

    let spaces = [b' '; 20];
    let mut o3 = [0u8; 20];
    assert_eq!(blk::trim_serial(&spaces, &mut o3), 0);

    let zeros = [0u8; 20];
    let mut o4 = [0u8; 20];
    assert_eq!(blk::trim_serial(&zeros, &mut o4), 0);

    let mut sl = [0u8; 20];
    sl[..3].copy_from_slice(b"a/b");
    let mut o5 = [0u8; 20];
    let n5 = blk::trim_serial(&sl, &mut o5);
    assert_eq!(&o5[..n5], b"ab");
}

#[test]
fn vd_name_base26() {
    let nm = |i: u32| {
        let mut b = [0u8; 8];
        let n = blk::vd_name(i, &mut b);
        String::from_utf8(b[..n].to_vec()).unwrap()
    };
    assert_eq!(nm(0), "vda");
    assert_eq!(nm(1), "vdb");
    assert_eq!(nm(25), "vdz");
    assert_eq!(nm(26), "vdaa");
    assert_eq!(nm(27), "vdab");
    assert_eq!(nm(701), "vdzz");
    assert_eq!(nm(702), "vdaaa");
}
