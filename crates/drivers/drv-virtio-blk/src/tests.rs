// Host-side encoding gate (verify-left, no boot). Drives the shared
// `virtio::blk` request encoder against a fake in-memory ring + a fake
// virtio-blk device, asserting:
//   * descriptor count + chaining for IN / OUT / FLUSH
//   * data-descriptor direction flag (IN device-writable, OUT readable)
//   * status descriptor always device-writable + chain-terminal
//   * header le encoding (type @0, sector @8)
//   * status decode (OK vs IOERR/UNSUPP)
// The fake device interprets the same `DescSpec` flags the kernel
// engine packs, so a direction-flag regression fails here.

use std::vec;
use std::vec::Vec;

use virtio::blk;
use virtio::queue::{VRING_DESC_F_NEXT, VRING_DESC_F_WRITE};

// ---- header encode ----------------------------------------------------

#[test]
fn header_le_layout() {
    let mut h = [0u8; 16];
    blk::encode_header(&mut h, blk::VIRTIO_BLK_T_OUT, 0x1122_3344_5566_7788);
    assert_eq!(&h[0..4], &1u32.to_le_bytes());         // type = T_OUT
    assert_eq!(&h[4..8], &0u32.to_le_bytes());         // reserved
    assert_eq!(&h[8..16], &0x1122_3344_5566_7788u64.to_le_bytes());
}

// ---- chain shape + direction flags ------------------------------------

#[test]
fn chain_in_data_is_device_writable() {
    let (d, n) = blk::build_chain(true, 0x1000, 0x2000, 512, 0x3000);
    assert_eq!(n, 3);
    // header: readable + NEXT
    assert_eq!(d[0].flags, VRING_DESC_F_NEXT);
    assert_eq!(d[0].next, 1);
    assert_eq!(d[0].len, 16);
    // data: device-WRITABLE for a read + NEXT
    assert_eq!(d[1].flags, VRING_DESC_F_NEXT | VRING_DESC_F_WRITE);
    assert_eq!(d[1].next, 2);
    assert_eq!(d[1].len, 512);
    // status: device-writable, terminal
    assert_eq!(d[2].flags, VRING_DESC_F_WRITE);
    assert_eq!(d[2].next, 0);
    assert_eq!(d[2].len, 1);
}

#[test]
fn chain_out_data_is_device_readable() {
    let (d, n) = blk::build_chain(false, 0x1000, 0x2000, 512, 0x3000);
    assert_eq!(n, 3);
    // data: NO F_WRITE for a write (device reads it) + NEXT
    assert_eq!(d[1].flags, VRING_DESC_F_NEXT);
    assert_eq!(d[1].flags & VRING_DESC_F_WRITE, 0);
    // status still device-writable
    assert_eq!(d[2].flags, VRING_DESC_F_WRITE);
}

#[test]
fn chain_flush_omits_data() {
    let (d, n) = blk::build_chain(true, 0x1000, 0xdead, 0, 0x3000);
    assert_eq!(n, 2);
    assert_eq!(d[0].next, 1);                 // header → status
    assert_eq!(d[1].addr, 0x3000);            // status, not data
    assert_eq!(d[1].flags, VRING_DESC_F_WRITE);
    assert_eq!(d[1].next, 0);
}

// ---- desc packing -----------------------------------------------------

#[test]
fn pack_desc_word_layout() {
    let d = blk::DescSpec { addr: 0xCAFE, len: 512, flags: VRING_DESC_F_WRITE, next: 7 };
    let (w0, w1) = blk::pack_desc(&d);
    assert_eq!(w0, 0xCAFE);
    assert_eq!(w1 & 0xFFFF_FFFF, 512);
    assert_eq!((w1 >> 32) & 0xFFFF, VRING_DESC_F_WRITE as u64);
    assert_eq!((w1 >> 48) & 0xFFFF, 7);
}

// ---- status decode ----------------------------------------------------

#[test]
fn status_decode() {
    assert!(blk::decode_status(blk::VIRTIO_BLK_S_OK).is_ok());
    assert_eq!(blk::decode_status(blk::VIRTIO_BLK_S_IOERR), Err(1));
    assert_eq!(blk::decode_status(blk::VIRTIO_BLK_S_UNSUPP), Err(2));
}

// ---- end-to-end against a fake device + fake ring ---------------------

/// Fake flat memory addressed by the PAs `build_chain` emits. The fake
/// device walks the chain, honors the F_WRITE direction on the data
/// desc, and writes the status byte.
struct FakeMem {
    region: Vec<u8>,
    /// backing "disk" content keyed by sector.
    disk:   Vec<u8>,
}

impl FakeMem {
    fn new() -> Self {
        // 0x4000 of scratch; PAs from build_chain land at 0x1000/0x2000/0x3000.
        FakeMem { region: vec![0u8; 0x4000], disk: vec![0u8; 512 * 8] }
    }
    fn w(&mut self, pa: u64, bytes: &[u8]) {
        let off = pa as usize;
        self.region[off..off + bytes.len()].copy_from_slice(bytes);
    }
    fn r(&self, pa: u64, len: usize) -> &[u8] {
        let off = pa as usize;
        &self.region[off..off + len]
    }

    /// Process a chain as a virtio-blk device would: decode header,
    /// move data per the desc direction flags, set status OK.
    fn process(&mut self, descs: &[blk::DescSpec], n: usize) {
        // header desc = descs[0]
        let hdr = self.r(descs[0].addr, 16).to_vec();
        let type_ = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
        let sector = u64::from_le_bytes([
            hdr[8], hdr[9], hdr[10], hdr[11], hdr[12], hdr[13], hdr[14], hdr[15],
        ]);
        let status_desc = descs[n - 1];
        assert_eq!(status_desc.flags & VRING_DESC_F_WRITE, VRING_DESC_F_WRITE,
                   "status desc must be device-writable");
        if n == 3 {
            let data = descs[1];
            let dlen = data.len as usize;
            let dsec = (sector as usize) * 512;
            if type_ == blk::VIRTIO_BLK_T_IN {
                // device WRITES into data buffer — desc must allow it.
                assert_eq!(data.flags & VRING_DESC_F_WRITE, VRING_DESC_F_WRITE,
                           "read data desc must be device-writable");
                let src = self.disk[dsec..dsec + dlen].to_vec();
                self.w(data.addr, &src);
            } else {
                // device READS from data buffer — desc must NOT be writable.
                assert_eq!(data.flags & VRING_DESC_F_WRITE, 0,
                           "write data desc must be device-readable");
                let src = self.r(data.addr, dlen).to_vec();
                self.disk[dsec..dsec + dlen].copy_from_slice(&src);
            }
        }
        self.w(status_desc.addr, &[blk::VIRTIO_BLK_S_OK]);
    }
}

// ---- pure naming / sizing helpers ------------------------------------

#[test]
fn validate_blk_size_clamps() {
    // valid sizes pass through
    assert_eq!(blk::validate_blk_size(512), 512);
    assert_eq!(blk::validate_blk_size(4096), 4096);
    assert_eq!(blk::validate_blk_size(1024), 1024);
    // invalid → 512 default
    assert_eq!(blk::validate_blk_size(0), 512);
    assert_eq!(blk::validate_blk_size(100), 512);   // < 512
    assert_eq!(blk::validate_blk_size(511), 512);   // < 512
    assert_eq!(blk::validate_blk_size(1000), 512);  // not multiple of 512
    assert_eq!(blk::validate_blk_size(513), 512);
}

#[test]
fn capacity_blocks_4096() {
    // 2048 virtio sectors (512B) = 1 MiB; at blk_size 4096 → 256 blocks.
    assert_eq!(blk::capacity_blocks(2048, 4096), 256);
    // at blk_size 512 → 2048 blocks (1:1).
    assert_eq!(blk::capacity_blocks(2048, 512), 2048);
    // non-aligned capacity truncates down (last partial 4K block dropped).
    assert_eq!(blk::capacity_blocks(2049, 4096), 256);
    assert_eq!(blk::capacity_blocks(0, 4096), 0);
    assert_eq!(blk::capacity_blocks(100, 0), 0);   // guard
}

#[test]
fn trim_serial_edges() {
    let mut out = [0u8; 20];
    // normal serial, NUL-terminated.
    let mut s = [0u8; 20];
    s[..10].copy_from_slice(b"oxide-root");
    let n = blk::trim_serial(&s, &mut out);
    assert_eq!(&out[..n], b"oxide-root");
    // no NUL: full 20 printable bytes consumed.
    let full = [b'a'; 20];
    let mut o2 = [0u8; 20];
    let n2 = blk::trim_serial(&full, &mut o2);
    assert_eq!(n2, 20);
    assert_eq!(&o2[..n2], &full[..]);
    // all spaces → empty (spaces are skipped) → index naming upstream.
    let spaces = [b' '; 20];
    let mut o3 = [0u8; 20];
    assert_eq!(blk::trim_serial(&spaces, &mut o3), 0);
    // all zero → empty (NUL at byte 0).
    let zeros = [0u8; 20];
    let mut o4 = [0u8; 20];
    assert_eq!(blk::trim_serial(&zeros, &mut o4), 0);
    // embedded slash skipped (path-unsafe), surrounding kept.
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
        std::string::String::from_utf8(b[..n].to_vec()).unwrap()
    };
    assert_eq!(nm(0), "vda");
    assert_eq!(nm(1), "vdb");
    assert_eq!(nm(25), "vdz");
    assert_eq!(nm(26), "vdaa");
    assert_eq!(nm(27), "vdab");
    assert_eq!(nm(701), "vdzz");
    assert_eq!(nm(702), "vdaaa");
}

#[test]
fn sector_plan_blocks_to_sectors() {
    // blk_size 4096: 1 block = 8 virtio sectors.
    assert_eq!(blk::sector_plan(0, 1, 4096), Some((0, 8)));
    // start_block 3 → base virtio sector 24; len 2 blocks → 16 sectors.
    assert_eq!(blk::sector_plan(3, 2, 4096), Some((24, 16)));
    // blk_size 512: 1:1.
    assert_eq!(blk::sector_plan(7, 4, 512), Some((7, 4)));
    // blk_size 0 guard.
    assert_eq!(blk::sector_plan(0, 1, 0), None);
}

// ---- multi-sector roundtrip (the coverage gap) ------------------------

/// Drive a multi-sector transfer the way `submit_sync` does: plan the
/// 512B sector run via `sector_plan`, then per sector encode the
/// header at `base+s`, build the chain, run the fake device, and assert
/// each sector's bytes land at offset `s*512` of the logical block.
#[test]
fn multi_sector_4k_block_roundtrip() {
    let mut mem = FakeMem::new();
    let (hdr_pa, data_pa, status_pa) = (0x1000u64, 0x2000u64, 0x3000u64);
    let blk_size = 4096u32;
    let start_block = 0u64; // 4K block 0 = virtio sectors 0..8

    // Distinct payload per sector so a wrong offset/sector is caught.
    let mut payload = vec![0u8; blk_size as usize];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = ((i / 512) as u8) << 4 | ((i % 512) & 0x0f) as u8;
    }

    let (base, total) = blk::sector_plan(start_block, 1, blk_size).unwrap();
    assert_eq!((base, total), (0, 8));

    // WRITE each 512B sector.
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

    // READ the whole 4K block back, asserting each sector lands at the
    // right offset of the reconstructed buffer.
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
    assert_eq!(got, payload, "each sector must reconstruct at s*512");
    // Spot-check the per-sector tag survived (sector 5 high nibble = 5).
    assert_eq!(got[5 * 512] >> 4, 5);
}

// ---- multi-sector chunking (the perf fix) -----------------------------

#[test]
fn chunk_plan_steps_and_terminates() {
    // max=4 sectors/chunk; a 10-sector run from base 100.
    let plan = |i| blk::chunk_plan(100, 10, i, 4);
    // chunk 0: sectors 100..104, off 0
    assert_eq!(plan(0), Some((100, 4, 0)));
    // chunk 1: sectors 104..108, off 4*512
    assert_eq!(plan(1), Some((104, 4, 4 * 512)));
    // chunk 2: tail of 2 sectors (10 - 8), off 8*512
    assert_eq!(plan(2), Some((108, 2, 8 * 512)));
    // chunk 3: run exhausted
    assert_eq!(plan(3), None);
    // exact multiple terminates cleanly (8 sectors, max 4 → 2 chunks).
    assert_eq!(blk::chunk_plan(0, 8, 0, 4), Some((0, 4, 0)));
    assert_eq!(blk::chunk_plan(0, 8, 1, 4), Some((4, 4, 4 * 512)));
    assert_eq!(blk::chunk_plan(0, 8, 2, 4), None);
    // max=0 guard
    assert_eq!(blk::chunk_plan(0, 8, 0, 0), None);
}

/// FakeMem with a larger scratch region so a multi-sector data desc
/// (up to `max_sectors*512`) fits, plus a larger backing disk.
struct FakeMemBig {
    region: Vec<u8>,
    disk:   Vec<u8>,
}
impl FakeMemBig {
    fn new(region_bytes: usize, disk_bytes: usize) -> Self {
        FakeMemBig { region: vec![0u8; region_bytes], disk: vec![0u8; disk_bytes] }
    }
    fn w(&mut self, pa: u64, bytes: &[u8]) {
        let off = pa as usize;
        self.region[off..off + bytes.len()].copy_from_slice(bytes);
    }
    fn r(&self, pa: u64, len: usize) -> Vec<u8> {
        let off = pa as usize;
        self.region[off..off + len].to_vec()
    }
    /// Same chain semantics as FakeMem::process but the data desc may
    /// span many sectors: device moves `data.len` bytes starting at
    /// `sector*512` of the disk, honoring the F_WRITE direction.
    fn process(&mut self, descs: &[blk::DescSpec], n: usize) {
        let hdr = self.r(descs[0].addr, 16);
        let type_ = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
        let sector = u64::from_le_bytes([
            hdr[8], hdr[9], hdr[10], hdr[11], hdr[12], hdr[13], hdr[14], hdr[15],
        ]);
        let status_desc = descs[n - 1];
        assert_eq!(status_desc.flags & VRING_DESC_F_WRITE, VRING_DESC_F_WRITE);
        if n == 3 {
            let data = descs[1];
            let dlen = data.len as usize;
            let dsec = (sector as usize) * 512;
            if type_ == blk::VIRTIO_BLK_T_IN {
                assert_eq!(data.flags & VRING_DESC_F_WRITE, VRING_DESC_F_WRITE,
                           "read data desc must be device-writable");
                let src = self.disk[dsec..dsec + dlen].to_vec();
                self.w(data.addr, &src);
            } else {
                assert_eq!(data.flags & VRING_DESC_F_WRITE, 0,
                           "write data desc must be device-readable");
                let src = self.r(data.addr, dlen);
                self.disk[dsec..dsec + dlen].copy_from_slice(&src);
            }
        }
        self.w(status_desc.addr, &[blk::VIRTIO_BLK_S_OK]);
    }
}

/// Drive the EXACT chunk loop submit_sync runs (sector_plan → chunk_plan
/// → build_chain per chunk), for a request SPANNING MORE than the bounce
/// window (forces ≥2 chunks) AND for a request of EXACTLY bounce size
/// (single full chunk). Asserts every sector lands at the right buffer
/// offset and disk sector, both directions, with a small `max` standing
/// in for BOUNCE_DATA_SECTORS so the loop is exercised cheaply.
#[test]
fn submit_sync_chunk_loop_roundtrip() {
    // Small window to force chunking without 128 KiB of scratch.
    const MAX: u64 = 4;          // sectors per chunk (stand-in)
    const BLK_SIZE: u32 = 4096;  // 8 virtio sectors / block
    // Header @0x0, status @0x10, data @0x1000 (mirrors modern.rs layout).
    let (hdr_pa, status_pa, data_pa) = (0x0u64, 0x10u64, 0x1000u64);
    let region_bytes = data_pa as usize + (MAX as usize) * 512;

    // Cases: span > bounce window (3 blocks = 24 sectors → 6 chunks of
    // max 4) AND exactly bounce window (one chunk == MAX sectors).
    for &(start_block, len_blocks) in &[(2u64, 3u32), (0u64, 1u32 /*=8sec=2 chunks*/), (5u64, 1u32)] {
        // Buffer: distinct byte per (sector,offset) so a wrong sector or
        // byte offset is caught. Disk big enough for the addressed range.
        let (base, total) = blk::sector_plan(start_block, len_blocks, BLK_SIZE).unwrap();
        let nbytes = total as usize * 512;
        let disk_bytes = (base as usize + total as usize + 4) * 512;
        let mut mem = FakeMemBig::new(region_bytes, disk_bytes);

        let mut payload = vec![0u8; nbytes];
        for (i, b) in payload.iter_mut().enumerate() {
            let sec = base + (i / 512) as u64;
            *b = (sec as u8).wrapping_mul(7).wrapping_add((i % 512) as u8);
        }

        // WRITE: chunk loop (T_OUT, device-readable data desc).
        let mut idx = 0u64;
        let mut chunks_w = 0u32;
        while let Some((cbase, csec, off)) = blk::chunk_plan(base, total, idx, MAX) {
            let clen = csec as usize * 512;
            mem.w(data_pa, &payload[off..off + clen]);
            let mut hdr = [0u8; 16];
            blk::encode_header(&mut hdr, blk::VIRTIO_BLK_T_OUT, cbase);
            mem.w(hdr_pa, &hdr);
            let (descs, n) = blk::build_chain(false, hdr_pa, data_pa, clen as u32, status_pa);
            assert_eq!(descs[1].len as usize, clen, "data desc len = chunk_sectors*512");
            mem.process(&descs, n);
            assert_eq!(mem.r(status_pa, 1)[0], blk::VIRTIO_BLK_S_OK);
            idx += 1;
            chunks_w += 1;
        }

        // READ back via the same chunk loop (T_IN, device-writable).
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

        assert_eq!(got, payload, "every sector reconstructs at its buffer offset");
        assert_eq!(chunks_w, chunks_r);
        // ceil(total / MAX) chunks expected.
        let expect = (total + MAX - 1) / MAX;
        assert_eq!(chunks_w as u64, expect, "chunk count = ceil(total/max)");
    }
}

/// At the real BOUNCE_DATA_SECTORS window, a request EXACTLY one chunk
/// wide is a SINGLE round-trip, and one sector larger is two — proving
/// the round-trip collapse the perf fix delivers.
#[test]
fn bounce_window_single_vs_multi_roundtrip() {
    let max = blk::BOUNCE_DATA_SECTORS;
    // exactly one chunk
    assert_eq!(blk::chunk_plan(0, max, 0, max), Some((0, max, 0)));
    assert_eq!(blk::chunk_plan(0, max, 1, max), None);
    // one sector over → two chunks (1 round-trip → 2)
    assert_eq!(blk::chunk_plan(0, max + 1, 0, max), Some((0, max, 0)));
    assert_eq!(blk::chunk_plan(0, max + 1, 1, max),
               Some((max, 1, max as usize * 512)));
    assert_eq!(blk::chunk_plan(0, max + 1, 2, max), None);
    // a 4 KiB ext4 block (8 sectors) is one chunk → 8 round-trips → 1.
    assert_eq!(blk::chunk_plan(0, 8, 0, max), Some((0, 8, 0)));
    assert_eq!(blk::chunk_plan(0, 8, 1, max), None);
}

#[test]
fn roundtrip_write_then_read() {
    let mut mem = FakeMem::new();
    let (hdr_pa, data_pa, status_pa) = (0x1000u64, 0x2000u64, 0x3000u64);
    let sector = 3u64;

    // WRITE: stage payload, encode header T_OUT, build chain, run device.
    let payload: Vec<u8> = (0..512u32).map(|i| (i & 0xff) as u8).collect();
    mem.w(data_pa, &payload);
    let mut hdr = [0u8; 16];
    blk::encode_header(&mut hdr, blk::VIRTIO_BLK_T_OUT, sector);
    mem.w(hdr_pa, &hdr);
    let (descs, n) = blk::build_chain(false, hdr_pa, data_pa, 512, status_pa);
    mem.process(&descs, n);
    assert_eq!(mem.r(status_pa, 1)[0], blk::VIRTIO_BLK_S_OK);
    assert!(blk::decode_status(mem.r(status_pa, 1)[0]).is_ok());

    // READ back from the same sector into a fresh data buffer.
    let read_data_pa = 0x2000u64; // reuse; zero it first
    mem.w(read_data_pa, &[0u8; 512]);
    let mut hdr2 = [0u8; 16];
    blk::encode_header(&mut hdr2, blk::VIRTIO_BLK_T_IN, sector);
    mem.w(hdr_pa, &hdr2);
    let (descs2, n2) = blk::build_chain(true, hdr_pa, read_data_pa, 512, status_pa);
    mem.process(&descs2, n2);
    assert_eq!(mem.r(status_pa, 1)[0], blk::VIRTIO_BLK_S_OK);
    // the data read back must equal what we wrote.
    assert_eq!(mem.r(read_data_pa, 512), &payload[..]);
}
