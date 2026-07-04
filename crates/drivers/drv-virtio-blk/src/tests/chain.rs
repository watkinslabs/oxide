use super::*;
use super::helpers::FakeMem;

#[test]
fn header_le_layout() {
    let mut h = [0u8; 16];
    blk::encode_header(&mut h, blk::VIRTIO_BLK_T_OUT, 0x1122_3344_5566_7788);
    assert_eq!(&h[0..4], &1u32.to_le_bytes());
    assert_eq!(&h[4..8], &0u32.to_le_bytes());
    assert_eq!(&h[8..16], &0x1122_3344_5566_7788u64.to_le_bytes());
}

#[test]
fn chain_in_data_is_device_writable() {
    let (d, n) = blk::build_chain(true, 0x1000, 0x2000, 512, 0x3000);
    assert_eq!(n, 3);
    assert_eq!(d[0].flags, VRING_DESC_F_NEXT);
    assert_eq!(d[0].next, 1);
    assert_eq!(d[0].len, 16);
    assert_eq!(d[1].flags, VRING_DESC_F_NEXT | VRING_DESC_F_WRITE);
    assert_eq!(d[1].next, 2);
    assert_eq!(d[1].len, 512);
    assert_eq!(d[2].flags, VRING_DESC_F_WRITE);
    assert_eq!(d[2].next, 0);
    assert_eq!(d[2].len, 1);
}

#[test]
fn chain_out_data_is_device_readable() {
    let (d, n) = blk::build_chain(false, 0x1000, 0x2000, 512, 0x3000);
    assert_eq!(n, 3);
    assert_eq!(d[1].flags, VRING_DESC_F_NEXT);
    assert_eq!(d[1].flags & VRING_DESC_F_WRITE, 0);
    assert_eq!(d[2].flags, VRING_DESC_F_WRITE);
}

#[test]
fn chain_flush_omits_data() {
    let (d, n) = blk::build_chain(true, 0x1000, 0xdead, 0, 0x3000);
    assert_eq!(n, 2);
    assert_eq!(d[0].next, 1);
    assert_eq!(d[1].addr, 0x3000);
    assert_eq!(d[1].flags, VRING_DESC_F_WRITE);
    assert_eq!(d[1].next, 0);
}

#[test]
fn pack_desc_word_layout() {
    let d = blk::DescSpec { addr: 0xCAFE, len: 512, flags: VRING_DESC_F_WRITE, next: 7 };
    let (w0, w1) = blk::pack_desc(&d);
    assert_eq!(w0, 0xCAFE);
    assert_eq!(w1 & 0xFFFF_FFFF, 512);
    assert_eq!((w1 >> 32) & 0xFFFF, VRING_DESC_F_WRITE as u64);
    assert_eq!((w1 >> 48) & 0xFFFF, 7);
}

#[test]
fn status_decode() {
    assert!(blk::decode_status(blk::VIRTIO_BLK_S_OK).is_ok());
    assert_eq!(blk::decode_status(blk::VIRTIO_BLK_S_IOERR), Err(1));
    assert_eq!(blk::decode_status(blk::VIRTIO_BLK_S_UNSUPP), Err(2));
}

#[test]
fn multi_sector_4k_block_roundtrip() {
    let mut mem = FakeMem::new();
    let (hdr_pa, data_pa, status_pa) = (0x1000u64, 0x2000u64, 0x3000u64);
    let blk_size = 4096u32;
    let start_block = 0u64;

    let mut payload = vec![0u8; blk_size as usize];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = ((i / 512) as u8) << 4 | ((i % 512) & 0x0f) as u8;
    }

    let (base, total) = blk::sector_plan(start_block, 1, blk_size).unwrap();
    assert_eq!((base, total), (0, 8));

    for s in 0..total {
        let off = (s as usize) * 512;
        mem.w(data_pa, &payload[off..off + 512]);
        let mut hdr = [0u8; 16];
        blk::encode_header(&mut hdr, blk::VIRTIO_BLK_T_OUT, base + s);
        mem.w(hdr_pa, &hdr);
        let (descs, n) = blk::build_chain(false, hdr_pa, data_pa, 512, status_pa);
        mem.process(&descs, n);
        assert_eq!(mem.r(status_pa, 1)[0], blk::VIRTIO_BLK_S_OK);
    }

    let mut got = vec![0u8; blk_size as usize];
    for s in 0..total {
        let off = (s as usize) * 512;
        mem.w(data_pa, &[0u8; 512]);
        let mut hdr = [0u8; 16];
        blk::encode_header(&mut hdr, blk::VIRTIO_BLK_T_IN, base + s);
        mem.w(hdr_pa, &hdr);
        let (descs, n) = blk::build_chain(true, hdr_pa, data_pa, 512, status_pa);
        mem.process(&descs, n);
        got[off..off + 512].copy_from_slice(mem.r(data_pa, 512));
    }
    assert_eq!(got, payload);
    assert_eq!(got[5 * 512] >> 4, 5);
}

#[test]
fn roundtrip_write_then_read() {
    let mut mem = FakeMem::new();
    let (hdr_pa, data_pa, status_pa) = (0x1000u64, 0x2000u64, 0x3000u64);
    let sector = 3u64;

    let payload: Vec<u8> = (0..512u32).map(|i| (i & 0xff) as u8).collect();
    mem.w(data_pa, &payload);
    let mut hdr = [0u8; 16];
    blk::encode_header(&mut hdr, blk::VIRTIO_BLK_T_OUT, sector);
    mem.w(hdr_pa, &hdr);
    let (descs, n) = blk::build_chain(false, hdr_pa, data_pa, 512, status_pa);
    mem.process(&descs, n);
    assert_eq!(mem.r(status_pa, 1)[0], blk::VIRTIO_BLK_S_OK);
    assert!(blk::decode_status(mem.r(status_pa, 1)[0]).is_ok());

    mem.w(data_pa, &[0u8; 512]);
    let mut hdr2 = [0u8; 16];
    blk::encode_header(&mut hdr2, blk::VIRTIO_BLK_T_IN, sector);
    mem.w(hdr_pa, &hdr2);
    let (descs2, n2) = blk::build_chain(true, hdr_pa, data_pa, 512, status_pa);
    mem.process(&descs2, n2);
    assert_eq!(mem.r(status_pa, 1)[0], blk::VIRTIO_BLK_S_OK);
    assert_eq!(mem.r(data_pa, 512), &payload[..]);
}
