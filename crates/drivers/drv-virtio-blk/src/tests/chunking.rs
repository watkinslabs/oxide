use super::*;
use super::helpers::FakeMemBig;

#[test]
fn sector_plan_blocks_to_sectors() {
    assert_eq!(blk::sector_plan(0, 1, 4096), Some((0, 8)));
    assert_eq!(blk::sector_plan(3, 2, 4096), Some((24, 16)));
    assert_eq!(blk::sector_plan(7, 4, 512), Some((7, 4)));
    assert_eq!(blk::sector_plan(0, 1, 0), None);
}

#[test]
fn chunk_plan_steps_and_terminates() {
    let plan = |i| blk::chunk_plan(100, 10, i, 4);
    assert_eq!(plan(0), Some((100, 4, 0)));
    assert_eq!(plan(1), Some((104, 4, 4 * 512)));
    assert_eq!(plan(2), Some((108, 2, 8 * 512)));
    assert_eq!(plan(3), None);
    assert_eq!(blk::chunk_plan(0, 8, 0, 4), Some((0, 4, 0)));
    assert_eq!(blk::chunk_plan(0, 8, 1, 4), Some((4, 4, 4 * 512)));
    assert_eq!(blk::chunk_plan(0, 8, 2, 4), None);
    assert_eq!(blk::chunk_plan(0, 8, 0, 0), None);
}

#[test]
fn submit_sync_chunk_loop_roundtrip() {
    const MAX: u64 = 4;
    const BLK_SIZE: u32 = 4096;
    let (hdr_pa, status_pa, data_pa) = (0x0u64, 0x10u64, 0x1000u64);
    let region_bytes = data_pa as usize + (MAX as usize) * 512;

    for &(start_block, len_blocks) in &[(2u64, 3u32), (0u64, 1u32), (5u64, 1u32)] {
        let (base, total) = blk::sector_plan(start_block, len_blocks, BLK_SIZE).unwrap();
        let nbytes = total as usize * 512;
        let disk_bytes = (base as usize + total as usize + 4) * 512;
        let mut mem = FakeMemBig::new(region_bytes, disk_bytes);

        let mut payload = vec![0u8; nbytes];
        for (i, b) in payload.iter_mut().enumerate() {
            let sec = base + (i / 512) as u64;
            *b = (sec as u8).wrapping_mul(7).wrapping_add((i % 512) as u8);
        }

        let mut idx = 0u64;
        let mut chunks_w = 0u32;
        while let Some((cbase, csec, off)) = blk::chunk_plan(base, total, idx, MAX) {
            let clen = csec as usize * 512;
            mem.w(data_pa, &payload[off..off + clen]);
            let mut hdr = [0u8; 16];
            blk::encode_header(&mut hdr, blk::VIRTIO_BLK_T_OUT, cbase);
            mem.w(hdr_pa, &hdr);
            let (descs, n) = blk::build_chain(false, hdr_pa, data_pa, clen as u32, status_pa);
            assert_eq!(descs[1].len as usize, clen);
            mem.process(&descs, n);
            assert_eq!(mem.r(status_pa, 1)[0], blk::VIRTIO_BLK_S_OK);
            idx += 1;
            chunks_w += 1;
        }

        let mut got = vec![0u8; nbytes];
        idx = 0;
        let mut chunks_r = 0u32;
        while let Some((cbase, csec, off)) = blk::chunk_plan(base, total, idx, MAX) {
            let clen = csec as usize * 512;
            mem.w(data_pa, &vec![0u8; clen]);
            let mut hdr = [0u8; 16];
            blk::encode_header(&mut hdr, blk::VIRTIO_BLK_T_IN, cbase);
            mem.w(hdr_pa, &hdr);
            let (descs, n) = blk::build_chain(true, hdr_pa, data_pa, clen as u32, status_pa);
            mem.process(&descs, n);
            got[off..off + clen].copy_from_slice(&mem.r(data_pa, clen));
            idx += 1;
            chunks_r += 1;
        }

        assert_eq!(got, payload);
        assert_eq!(chunks_w, chunks_r);
        let expect = (total + MAX - 1) / MAX;
        assert_eq!(chunks_w as u64, expect);
    }
}

#[test]
fn bounce_window_single_vs_multi_roundtrip() {
    let max = blk::BOUNCE_DATA_SECTORS;
    assert_eq!(blk::chunk_plan(0, max, 0, max), Some((0, max, 0)));
    assert_eq!(blk::chunk_plan(0, max, 1, max), None);
    assert_eq!(blk::chunk_plan(0, max + 1, 0, max), Some((0, max, 0)));
    assert_eq!(blk::chunk_plan(0, max + 1, 1, max), Some((max, 1, max as usize * 512)));
    assert_eq!(blk::chunk_plan(0, max + 1, 2, max), None);
    assert_eq!(blk::chunk_plan(0, 8, 0, max), Some((0, 8, 0)));
    assert_eq!(blk::chunk_plan(0, 8, 1, max), None);
}
