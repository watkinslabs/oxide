// Host tests for the driver's zone decisions. Everything here runs against a
// `BlkState` with no live ring, which is enough for every REFUSAL: each one
// returns before the engine is touched, and an `Eio` would mean the check did
// not fire and the request reached a device that does not exist.

use super::*;

fn info(zone_sectors: u32, max_append: u32) -> vz::ZonedInfo {
    vz::ZonedInfo {
        zone_sectors,
        max_open_zones: 8,
        max_active_zones: 6,
        max_append_sectors: max_append,
        write_granularity: 4096,
    }
}

/// 4 KiB-block disk, 1024-sector (512 KiB) zones: 128 blocks per zone.
fn zoned_disk() -> BlkState { BlkState::for_test_zoned(info(1024, 256), 4096) }

fn flat_disk() -> BlkState { BlkState::for_test_cfg(0) }

#[test]
fn a_flat_disk_reports_no_zones_and_no_zone_size() {
    let d = flat_disk();
    assert_eq!(d.zoned, None);
    assert_eq!(d.zone_sectors(), 0);
    assert!(d.read_zone_report().is_none());
}

/// Every zone operation on a drive with no zones is a refusal, never a silent
/// success. An `Ok(())` here would tell a caller a transition happened.
#[test]
fn a_flat_disk_refuses_every_zone_operation_as_unsupported() {
    let d = flat_disk();
    for op in [ZoneMgmtOp::Open, ZoneMgmtOp::Close, ZoneMgmtOp::Finish,
               ZoneMgmtOp::Reset, ZoneMgmtOp::ResetAll] {
        assert_eq!(d.issue_zone_mgmt(op, 0), Err(BlockError::Eopnotsupp), "{op:?}");
    }
    assert_eq!(d.issue_zone_append(0, &[0u8; 4096]), Err(BlockError::Eopnotsupp));
}

/// A management command names a zone by its first block. Rounding one that
/// points into the middle of a zone would reset a zone nobody named, so it is
/// refused — and refused HERE, where the caller is identifiable, rather than
/// as a status byte from the drive.
#[test]
fn a_management_command_inside_a_zone_is_refused_not_rounded() {
    let d = zoned_disk();
    for op in [ZoneMgmtOp::Open, ZoneMgmtOp::Close, ZoneMgmtOp::Finish, ZoneMgmtOp::Reset] {
        // Block 1 is inside zone 0; block 127 is its last block.
        assert_eq!(d.issue_zone_mgmt(op, 1), Err(BlockError::Einval), "{op:?} at block 1");
        assert_eq!(d.issue_zone_mgmt(op, 127), Err(BlockError::Einval), "{op:?} at block 127");
    }
}

/// A legal address gets past the alignment check and reaches the engine,
/// which has no ring in a test and answers `Eio`. That distinction is the
/// point: `Einval` above means the check fired, `Eio` here means it did not.
#[test]
fn a_management_command_at_a_zone_start_reaches_the_engine() {
    let d = zoned_disk();
    for block in [0u64, 128, 256, 4096] {
        assert_eq!(d.issue_zone_mgmt(ZoneMgmtOp::Reset, block), Err(BlockError::Eio),
                   "block {block} should have passed validation");
    }
    // Reset-all addresses the whole drive, so no block is checked.
    assert_eq!(d.issue_zone_mgmt(ZoneMgmtOp::ResetAll, 999), Err(BlockError::Eio));
}

#[test]
fn an_append_must_address_a_zone_start_and_carry_whole_blocks() {
    let d = zoned_disk();
    assert_eq!(d.issue_zone_append(1, &[0u8; 4096]), Err(BlockError::Einval), "not a zone start");
    assert_eq!(d.issue_zone_append(0, &[0u8; 100]), Err(BlockError::Einval), "partial block");
    assert_eq!(d.issue_zone_append(0, &[]), Err(BlockError::Einval), "empty append");
    assert_eq!(d.issue_zone_append(0, &[0u8; 4096]), Err(BlockError::Eio), "valid, reached engine");
}

/// An append is ONE placement and the caller learns exactly one landing
/// block. Splitting an oversized buffer into two appends would place half the
/// data somewhere the caller is never told about, so it is refused.
#[test]
fn an_append_past_the_drive_limit_is_refused_never_split() {
    // A 64-sector append limit is 8 blocks of 4 KiB — well inside the
    // engine's 128 KiB bounce window, so only the DRIVE's limit can refuse
    // the oversized buffer. Sizing the case against a limit at or above the
    // window would let the window's own check answer instead, and the
    // append-limit check could be deleted with nothing turning red.
    let d = BlkState::for_test_zoned(info(1024, 64), 4096);
    assert_eq!(d.issue_zone_append(0, &alloc::vec![0u8; 8 * 4096]), Err(BlockError::Eio),
               "exactly the limit is legal");
    assert_eq!(d.issue_zone_append(0, &alloc::vec![0u8; 9 * 4096]), Err(BlockError::Einval),
               "one block past the limit");
    assert!(9 * 4096 < blk::BOUNCE_DATA_BYTES, "the window must not be what refused it");

    // The window is a second, independent bound: a drive whose append limit
    // exceeds it still cannot append more than one chain carries.
    let wide = BlkState::for_test_zoned(info(1 << 20, 1 << 20), 4096);
    let over = blk::BOUNCE_DATA_BYTES + 4096;
    assert_eq!(wide.issue_zone_append(0, &alloc::vec![0u8; over]), Err(BlockError::Einval));
}

/// A run that leaves its zone cannot go down the single-chain path, which
/// has no way to cut it. It is declined so the chunking path takes it.
#[test]
fn a_run_leaving_its_zone_is_not_one_chain() {
    let d = zoned_disk();
    assert!(d.run_within_one_zone(0, 1024), "exactly one zone");
    assert!(d.run_within_one_zone(512, 512), "up to the boundary");
    assert!(!d.run_within_one_zone(512, 513), "one sector past it");
    assert!(!d.run_within_one_zone(0, 2048), "two whole zones");
    // A drive with no zones has no boundary to leave.
    assert!(flat_disk().run_within_one_zone(0, 1 << 20));
}

/// The two resource statuses are transient limits a caller can act on, and
/// an unaligned write pointer is a placement mistake it can correct. Folding
/// any of them into `Eio` turns a fixable condition into a broken drive.
#[test]
fn each_zone_status_maps_to_its_own_error() {
    assert_eq!(zone_block_error(vz::VIRTIO_BLK_S_ZONE_OPEN_RESOURCE), BlockError::Etoomanyrefs);
    assert_eq!(zone_block_error(vz::VIRTIO_BLK_S_ZONE_ACTIVE_RESOURCE), BlockError::Eoverflow);
    assert_eq!(zone_block_error(vz::VIRTIO_BLK_S_ZONE_UNALIGNED_WP), BlockError::Einval);
    assert_eq!(zone_block_error(vz::VIRTIO_BLK_S_ZONE_INVALID_CMD), BlockError::Einval);
    assert_eq!(zone_block_error(blk::VIRTIO_BLK_S_UNSUPP), BlockError::Eopnotsupp);
    assert_eq!(zone_block_error(blk::VIRTIO_BLK_S_IOERR), BlockError::Eio);
    // The generic and the zone errors must stay distinguishable from each other.
    let open = zone_block_error(vz::VIRTIO_BLK_S_ZONE_OPEN_RESOURCE);
    let active = zone_block_error(vz::VIRTIO_BLK_S_ZONE_ACTIVE_RESOURCE);
    assert_ne!(open, active);
    assert_ne!(open, BlockError::Eio);
    assert_ne!(active, BlockError::Eio);
}

/// Every management operation maps to its own command number. Two operations
/// sharing one would, for instance, reset a zone that was asked to be closed.
#[test]
fn each_management_operation_has_its_own_command() {
    let all = [(ZoneMgmtOp::Open, vz::VIRTIO_BLK_T_ZONE_OPEN),
               (ZoneMgmtOp::Close, vz::VIRTIO_BLK_T_ZONE_CLOSE),
               (ZoneMgmtOp::Finish, vz::VIRTIO_BLK_T_ZONE_FINISH),
               (ZoneMgmtOp::Reset, vz::VIRTIO_BLK_T_ZONE_RESET),
               (ZoneMgmtOp::ResetAll, vz::VIRTIO_BLK_T_ZONE_RESET_ALL)];
    for (op, want) in all { assert_eq!(mgmt_command(op), want, "{op:?}"); }
}

/// The report reply is device-written data. A driver that declared the data
/// descriptor device-READABLE would read back its own zeros, which decode as
/// a drive with no zones — a silent wrong answer, not a failure.
#[test]
fn the_report_reply_is_device_written_and_the_commands_are_not() {
    use crate::modern::request::device_writes_data;
    assert!(device_writes_data(vz::VIRTIO_BLK_T_ZONE_REPORT));
    assert!(device_writes_data(blk::VIRTIO_BLK_T_IN));
    assert!(device_writes_data(blk::VIRTIO_BLK_T_GET_ID));
    for t in [vz::VIRTIO_BLK_T_ZONE_APPEND, vz::VIRTIO_BLK_T_ZONE_OPEN,
              vz::VIRTIO_BLK_T_ZONE_RESET, blk::VIRTIO_BLK_T_OUT, blk::VIRTIO_BLK_T_FLUSH] {
        assert!(!device_writes_data(t), "type {t} carries driver-written data");
    }
}

/// The report buffer must hold a whole number of descriptors after its
/// header, and must fit the engine's bounce window — a larger request is
/// rejected by `submit` and the walk would never make progress.
#[test]
fn the_report_buffer_fits_the_bounce_window_exactly() {
    assert!(REPORT_BUFFER_BYTES <= blk::BOUNCE_DATA_BYTES);
    assert_eq!(vz::zones_per_buffer(REPORT_BUFFER_BYTES), ZONES_PER_REQUEST);
}

/// Sector and block units are not interchangeable, and every conversion in
/// this module is in one direction at one place.
#[test]
fn zone_geometry_converts_between_sectors_and_this_disks_blocks() {
    let d = zoned_disk();
    assert_eq!(d.sectors_per_block(), 8, "4096-byte blocks over 512-byte sectors");
    assert_eq!(d.sectors_to_blocks(1024), 128, "one zone is 128 blocks");
    assert_eq!(d.blocks_to_sectors(128), Some(1024));
    assert_eq!(d.blocks_to_sectors(u64::MAX), None, "overflow is refused, not wrapped");

    // A 512-byte-block disk addresses blocks and sectors alike.
    let d = BlkState::for_test_zoned(info(1024, 256), 512);
    assert_eq!(d.sectors_per_block(), 1);
    assert_eq!(d.sectors_to_blocks(1024), 1024);
}

/// The alignment gate the probe applies: a zone that is not a whole number of
/// this disk's blocks has boundaries no block-addressed caller can name.
#[test]
fn a_zone_must_be_a_whole_number_of_logical_blocks() {
    assert!(vz::zone_size_block_aligned(1024, 4096), "512 KiB zone, 4 KiB blocks");
    assert!(vz::zone_size_block_aligned(8, 4096), "exactly one block");
    assert!(!vz::zone_size_block_aligned(4, 4096), "half a block");
    assert!(!vz::zone_size_block_aligned(0, 4096));
    assert!(!vz::zone_size_block_aligned(1024, 0));
    assert!(vz::zone_size_block_aligned(1, 512));
}

// --- the report walk ------------------------------------------------------

fn descriptor(cap: u64, start: u64, wp: u64, ty: u8, state: u8) -> [u8; vz::ZONE_DESCRIPTOR_BYTES] {
    let mut d = [0u8; vz::ZONE_DESCRIPTOR_BYTES];
    d[0..8].copy_from_slice(&cap.to_le_bytes());
    d[8..16].copy_from_slice(&start.to_le_bytes());
    d[16..24].copy_from_slice(&wp.to_le_bytes());
    d[24] = ty;
    d[25] = state;
    d
}

/// A reply carrying `descs`, in a buffer sized for `slots` of them, with a
/// header count of `claimed`.
fn reply(descs: &[[u8; vz::ZONE_DESCRIPTOR_BYTES]], slots: usize, claimed: u64) -> Vec<u8> {
    let mut b = alloc::vec![0u8; vz::ZONE_REPORT_HEADER_BYTES + slots * vz::ZONE_DESCRIPTOR_BYTES];
    b[0..8].copy_from_slice(&claimed.to_le_bytes());
    for (i, d) in descs.iter().enumerate() {
        let off = vz::ZONE_REPORT_HEADER_BYTES + i * vz::ZONE_DESCRIPTOR_BYTES;
        b[off..off + vz::ZONE_DESCRIPTOR_BYTES].copy_from_slice(d);
    }
    b
}

/// A whole reply, in the disk's own block unit. Sectors and blocks differ by
/// a factor of eight here, so any conversion left out shows up as a zone map
/// eight times too large.
#[test]
fn a_reply_decodes_into_this_disks_blocks() {
    let i = info(1024, 256);
    let b = reply(&[
        descriptor(1024, 0, 0, vz::VIRTIO_BLK_ZT_CONV, vz::VIRTIO_BLK_ZS_NOT_WP),
        descriptor(1000, 1024, 1536, vz::VIRTIO_BLK_ZT_SWR, vz::VIRTIO_BLK_ZS_IOPEN),
    ], 2, 2);
    let mut out = Vec::new();
    // 8 sectors per 4 KiB block; a 4096-sector drive.
    let next = absorb_report(&b, &i, 4096, 8, &mut out).expect("well-formed reply");
    assert_eq!(next, 2048, "one zone size past the last descriptor's start");
    assert_eq!(out.len(), 2);

    assert_eq!(out[0].start_block, 0);
    assert_eq!(out[0].len_blocks, 128);
    assert_eq!(out[0].capacity_blocks, 128);
    assert_eq!(out[0].kind, block::ZoneType::Conventional);
    assert_eq!(out[0].wp_block, None);
    assert_eq!(out[0].cond, block::ZoneCond::NotWp);

    assert_eq!(out[1].start_block, 128);
    assert_eq!(out[1].len_blocks, 128);
    assert_eq!(out[1].capacity_blocks, 125, "a short-capacity zone keeps its full length");
    assert_eq!(out[1].wp_block, Some(192));
    assert_eq!(out[1].cond, block::ZoneCond::ImplicitOpen);
}

/// The buffer holds four zones; the device answered with one. Walking the
/// buffer instead of the header count reads the untouched tail, whose zeros
/// decode as an undefined zone type — which is why this must never happen.
#[test]
fn the_walk_stops_at_the_devices_count_not_the_buffers_capacity() {
    let i = info(1024, 256);
    let b = reply(&[descriptor(1024, 0, 0, vz::VIRTIO_BLK_ZT_SWR, vz::VIRTIO_BLK_ZS_EMPTY)], 4, 1);
    let mut out = Vec::new();
    assert_eq!(absorb_report(&b, &i, 8192, 8, &mut out), Some(1024));
    assert_eq!(out.len(), 1, "the three untouched slots are not zones");
}

/// A device claiming more zones than the buffer holds must not make the walk
/// read past the reply.
#[test]
fn a_count_larger_than_the_buffer_is_clamped_to_the_buffer() {
    let i = info(1024, 256);
    let b = reply(&[descriptor(1024, 0, 0, vz::VIRTIO_BLK_ZT_SWR, vz::VIRTIO_BLK_ZS_EMPTY)], 1, 99);
    let mut out = Vec::new();
    assert_eq!(absorb_report(&b, &i, 8192, 8, &mut out), Some(1024));
    assert_eq!(out.len(), 1);
}

/// An undefined type or state has an unknown write rule. The whole reply is
/// rejected rather than partly trusted: a map missing one zone is a map that
/// places data in it.
#[test]
fn a_malformed_descriptor_rejects_the_reply() {
    let i = info(1024, 256);
    for bad in [descriptor(1024, 0, 0, 9, vz::VIRTIO_BLK_ZS_EMPTY),
                descriptor(1024, 0, 0, vz::VIRTIO_BLK_ZT_SWR, 7)] {
        let b = reply(&[bad], 1, 1);
        let mut out = Vec::new();
        assert_eq!(absorb_report(&b, &i, 8192, 8, &mut out), None);
    }
    // A truncated reply has no header to read.
    let mut out = Vec::new();
    assert_eq!(absorb_report(&[0u8; 8], &i, 8192, 8, &mut out), None);
}

/// An empty reply advances nothing, which is what ends the walk rather than
/// looping on a device that keeps answering with no zones.
#[test]
fn an_empty_reply_advances_nothing() {
    let i = info(1024, 256);
    let b = reply(&[], 4, 0);
    let mut out = Vec::new();
    assert_eq!(absorb_report(&b, &i, 8192, 8, &mut out), Some(0));
    assert!(out.is_empty());
}
