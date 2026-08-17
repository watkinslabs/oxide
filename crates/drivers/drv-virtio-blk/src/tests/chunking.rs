use super::*;
use super::helpers::FakeMemBig;
use virtio::blk::zoned::zone_bounded_chunk;

/// The engine's chunk loop, as a cursor. Yields `(sector, sectors, offset)`
/// per chunk exactly as `submit_sync` steps it, so a roundtrip driven from
/// here exercises the loop the engine actually runs. `zone_sectors == 0` is a
/// drive with no zones and no boundary.
fn chunks(base: u64, total: u64, max: u64, zone_sectors: u32) -> Vec<(u64, u64, usize)> {
    let (mut at, mut left, mut off) = (base, total, 0usize);
    let mut out = Vec::new();
    while let Some(n) = zone_bounded_chunk(at, left, max, zone_sectors) {
        out.push((at, n, off));
        at += n;
        left -= n;
        off += n as usize * 512;
    }
    out
}

#[test]
fn sector_plan_blocks_to_sectors() {
    assert_eq!(blk::sector_plan(0, 1, 4096), Some((0, 8)));
    assert_eq!(blk::sector_plan(3, 2, 4096), Some((24, 16)));
    assert_eq!(blk::sector_plan(7, 4, 512), Some((7, 4)));
    assert_eq!(blk::sector_plan(0, 1, 0), None);
}

#[test]
fn the_chunk_loop_steps_and_terminates() {
    assert_eq!(chunks(100, 10, 4, 0),
               vec![(100, 4, 0), (104, 4, 4 * 512), (108, 2, 8 * 512)]);
    assert_eq!(chunks(0, 8, 4, 0), vec![(0, 4, 0), (4, 4, 4 * 512)]);
    assert_eq!(chunks(0, 8, 0, 0), vec![], "a zero window yields nothing rather than spinning");
    assert_eq!(chunks(0, 0, 4, 0), vec![], "an empty run yields nothing");
}

/// The same loop on a zoned drive: the window still bounds each chunk, and
/// the zone boundary cuts whichever chunk would cross it.
#[test]
fn the_chunk_loop_cuts_at_zone_boundaries() {
    // 16-sector zones, an 8-sector window, a run from 12 through two zones.
    assert_eq!(chunks(12, 20, 8, 16),
               vec![(12, 4, 0), (16, 8, 4 * 512), (24, 8, 12 * 512)]);
    for (at, n, _) in chunks(12, 20, 8, 16) {
        assert_eq!(at / 16, (at + n - 1) / 16, "chunk {at}+{n} left its zone");
    }
    // A run that fits one zone is one chunk, exactly as on a flat drive.
    assert_eq!(chunks(16, 8, 8, 16), vec![(16, 8, 0)]);
}

#[test]
fn submit_sync_chunk_loop_roundtrip() {
    const MAX: u64 = 4;
    const BLK_SIZE: u32 = 4096;
    let (hdr_pa, status_pa, data_pa) = (0x0u64, 0x10u64, 0x1000u64);
    let region_bytes = data_pa as usize + (MAX as usize) * 512;

    // The same roundtrip on a flat drive and on one with 8-sector zones. The
    // zoned pass cuts chunks the flat pass does not, and must still return
    // every byte written.
    for &zone_sectors in &[0u32, 8] {
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

        let plan = chunks(base, total, MAX, zone_sectors);
        let mut chunks_w = 0u32;
        for &(cbase, csec, off) in &plan {
            let clen = csec as usize * 512;
            mem.w(data_pa, &payload[off..off + clen]);
            let mut hdr = [0u8; 16];
            blk::encode_header(&mut hdr, blk::VIRTIO_BLK_T_OUT, cbase);
            mem.w(hdr_pa, &hdr);
            let (descs, n) = blk::build_chain(false, hdr_pa, data_pa, clen as u32, status_pa);
            assert_eq!(descs[1].len as usize, clen);
            mem.process(&descs, n);
            assert_eq!(mem.r(status_pa, 1)[0], blk::VIRTIO_BLK_S_OK);
            chunks_w += 1;
        }

        let mut got = vec![0u8; nbytes];
        let mut chunks_r = 0u32;
        for &(cbase, csec, off) in &plan {
            let clen = csec as usize * 512;
            mem.w(data_pa, &vec![0u8; clen]);
            let mut hdr = [0u8; 16];
            blk::encode_header(&mut hdr, blk::VIRTIO_BLK_T_IN, cbase);
            mem.w(hdr_pa, &hdr);
            let (descs, n) = blk::build_chain(true, hdr_pa, data_pa, clen as u32, status_pa);
            mem.process(&descs, n);
            got[off..off + clen].copy_from_slice(&mem.r(data_pa, clen));
            chunks_r += 1;
        }

        assert_eq!(got, payload, "zone_sectors={zone_sectors}");
        assert_eq!(chunks_w, chunks_r);
        // The run is covered exactly once, contiguously, with no chunk over
        // the window and none over a zone boundary.
        let mut expect_at = base;
        for &(cbase, csec, off) in &plan {
            assert_eq!(cbase, expect_at);
            assert_eq!(off, ((cbase - base) as usize) * 512);
            assert!(csec <= MAX && csec > 0);
            if zone_sectors != 0 {
                assert_eq!(cbase / zone_sectors as u64, (cbase + csec - 1) / zone_sectors as u64);
            }
            expect_at += csec;
        }
        assert_eq!(expect_at, base + total, "the plan covered the whole run");
        if zone_sectors == 0 {
            assert_eq!(chunks_w as u64, total.div_ceil(MAX));
        }
    }
    }
}

#[test]
fn bounce_window_single_vs_multi_roundtrip() {
    let max = blk::BOUNCE_DATA_SECTORS;
    assert_eq!(chunks(0, max, max, 0), vec![(0, max, 0)]);
    assert_eq!(chunks(0, max + 1, max, 0), vec![(0, max, 0), (max, 1, max as usize * 512)]);
    assert_eq!(chunks(0, 8, max, 0), vec![(0, 8, 0)]);
}
