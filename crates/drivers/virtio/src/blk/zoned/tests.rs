// Host tests for the zoned probe decision and report decode. Every case here
// is a place where a wrong answer places a write behind a drive's write
// pointer, so each asserts the refusal or the exact decoded value, never just
// "did not panic".

use super::*;

/// Build the 21-byte characteristics run the probe reads.
fn characteristics(
    zone_sectors: u32, max_open: u32, max_active: u32, max_append: u32, wg: u32, model: u8,
) -> [u8; BLK_CFG_ZONED_BYTES] {
    let mut c = [0u8; BLK_CFG_ZONED_BYTES];
    c[0..4].copy_from_slice(&zone_sectors.to_le_bytes());
    c[4..8].copy_from_slice(&max_open.to_le_bytes());
    c[8..12].copy_from_slice(&max_active.to_le_bytes());
    c[12..16].copy_from_slice(&max_append.to_le_bytes());
    c[16..20].copy_from_slice(&wg.to_le_bytes());
    c[20] = model;
    c
}

fn good() -> [u8; BLK_CFG_ZONED_BYTES] {
    characteristics(524_288, 14, 14, 2048, 4096, VIRTIO_BLK_Z_HM)
}

/// The characteristics block sits at 72 in the packed device config, right
/// after the secure-erase entries. An offset slip reads a neighbouring field
/// as a zone size, which is a plausible-looking number and a wrong drive.
#[test]
fn characteristics_offsets_match_the_packed_config() {
    assert_eq!(BLK_CFG_OFF_ZONE_SECTORS, 72);
    assert_eq!(BLK_CFG_OFF_MAX_OPEN_ZONES, 76);
    assert_eq!(BLK_CFG_OFF_MAX_ACTIVE_ZONES, 80);
    assert_eq!(BLK_CFG_OFF_MAX_APPEND_SECTORS, 84);
    assert_eq!(BLK_CFG_OFF_WRITE_GRANULARITY, 88);
    assert_eq!(BLK_CFG_OFF_ZONE_MODEL, 92);
    assert_eq!(BLK_CFG_ZONED_BYTES, (BLK_CFG_OFF_ZONE_MODEL - BLK_CFG_OFF_ZONE_SECTORS) as usize + 1);
}

/// The command numbers and the feature bit are the ABI. Each is used raw on
/// the wire, so a transcription error issues a different command entirely.
#[test]
fn command_numbers_are_the_wire_values() {
    assert_eq!(VIRTIO_BLK_F_ZONED, 1 << 17);
    assert_eq!(VIRTIO_BLK_T_ZONE_APPEND, 15);
    assert_eq!(VIRTIO_BLK_T_ZONE_REPORT, 16);
    assert_eq!(VIRTIO_BLK_T_ZONE_OPEN, 18);
    assert_eq!(VIRTIO_BLK_T_ZONE_CLOSE, 20);
    assert_eq!(VIRTIO_BLK_T_ZONE_FINISH, 22);
    assert_eq!(VIRTIO_BLK_T_ZONE_RESET, 24);
    assert_eq!(VIRTIO_BLK_T_ZONE_RESET_ALL, 26);
    assert_eq!(ZONE_REPORT_HEADER_BYTES, 64);
    assert_eq!(ZONE_DESCRIPTOR_BYTES, 64);
}

#[test]
fn a_host_managed_drive_is_attached_with_its_stated_limits() {
    let ZonedProbe::HostManaged(info) = probe_zoned(&good()) else { panic!("refused a good drive") };
    assert_eq!(info.zone_sectors, 524_288);
    assert_eq!(info.max_append_sectors, 2048);
    assert_eq!(info.write_granularity, 4096);
    assert_eq!(info.open_limit(), Some(14));
    assert_eq!(info.active_limit(), Some(14));
}

/// Zero is "no limit", not "nothing may be open". Reading it as a count makes
/// every open refuse on a drive that has no limit at all.
#[test]
fn a_zero_limit_means_unlimited_not_zero() {
    let c = characteristics(1024, 0, 0, 512, 4096, VIRTIO_BLK_Z_HM);
    let ZonedProbe::HostManaged(info) = probe_zoned(&c) else { panic!() };
    assert_eq!(info.open_limit(), None);
    assert_eq!(info.active_limit(), None);
}

/// A host-aware drive accepts any write order, so nothing above needs its
/// zone map to be correct — it is attached as an ordinary drive, exactly as
/// the reference does.
#[test]
fn host_aware_and_none_are_ordinary_drives() {
    for model in [VIRTIO_BLK_Z_NONE, VIRTIO_BLK_Z_HA] {
        let c = characteristics(1024, 4, 4, 512, 4096, model);
        assert_eq!(probe_zoned(&c), ZonedProbe::NotZoned, "model {model}");
    }
}

#[test]
fn an_unknown_model_is_refused_not_guessed() {
    for model in [3u8, 7, 255] {
        let c = characteristics(1024, 4, 4, 512, 4096, model);
        assert_eq!(probe_zoned(&c), ZonedProbe::Refuse(ZonedRefusal::UnknownModel(model)));
    }
}

#[test]
fn a_drive_with_no_write_granularity_is_refused() {
    let c = characteristics(1024, 4, 4, 512, 0, VIRTIO_BLK_Z_HM);
    assert_eq!(probe_zoned(&c), ZonedProbe::Refuse(ZonedRefusal::ZeroWriteGranularity));
}

#[test]
fn a_non_power_of_two_zone_size_is_refused() {
    for zs in [0u32, 3, 1000, 524_287] {
        let c = characteristics(zs, 4, 4, 512, 4096, VIRTIO_BLK_Z_HM);
        assert_eq!(probe_zoned(&c),
                   ZonedProbe::Refuse(ZonedRefusal::ZoneSectorsNotPowerOfTwo(zs)), "zs {zs}");
    }
}

#[test]
fn a_drive_that_admits_no_append_is_refused() {
    let c = characteristics(1024, 4, 4, 0, 4096, VIRTIO_BLK_Z_HM);
    assert_eq!(probe_zoned(&c), ZonedProbe::Refuse(ZonedRefusal::ZeroMaxAppendSectors));
}

/// An append limit below one write unit leaves no legal append at all.
#[test]
fn an_append_limit_below_the_write_unit_is_refused() {
    // 4 sectors = 2048 bytes, under a 4096-byte write granularity.
    let c = characteristics(1024, 4, 4, 4, 4096, VIRTIO_BLK_Z_HM);
    assert_eq!(probe_zoned(&c), ZonedProbe::Refuse(
        ZonedRefusal::AppendBelowWriteGranularity { write_granularity: 4096, max_append_sectors: 4 }));
    // Exactly one write unit is legal.
    let c = characteristics(1024, 4, 4, 8, 4096, VIRTIO_BLK_Z_HM);
    assert!(matches!(probe_zoned(&c), ZonedProbe::HostManaged(_)));
}

/// The granularity check runs before the zone-size check, so a drive that is
/// wrong in both ways is diagnosed by the first thing wrong rather than by
/// whichever check happens to be written first.
#[test]
fn refusal_order_names_the_first_fault() {
    let c = characteristics(0, 4, 4, 0, 0, VIRTIO_BLK_Z_HM);
    assert_eq!(probe_zoned(&c), ZonedProbe::Refuse(ZonedRefusal::ZeroWriteGranularity));
    let c = characteristics(0, 4, 4, 0, 4096, VIRTIO_BLK_Z_HM);
    assert_eq!(probe_zoned(&c), ZonedProbe::Refuse(ZonedRefusal::ZoneSectorsNotPowerOfTwo(0)));
}

/// A shift-based `max_append << 9` on a 32-bit value wraps for large limits
/// and can turn a legal drive into a refusal. The comparison is done in 64
/// bits so it cannot.
#[test]
fn a_huge_append_limit_does_not_wrap_into_a_refusal() {
    let c = characteristics(1024, 4, 4, 0x0080_0000, 4096, VIRTIO_BLK_Z_HM);
    assert!(matches!(probe_zoned(&c), ZonedProbe::HostManaged(_)));
}

// --- report decode ---------------------------------------------------------

fn descriptor(cap: u64, start: u64, wp: u64, ty: u8, state: u8) -> [u8; ZONE_DESCRIPTOR_BYTES] {
    let mut d = [0u8; ZONE_DESCRIPTOR_BYTES];
    d[0..8].copy_from_slice(&cap.to_le_bytes());
    d[8..16].copy_from_slice(&start.to_le_bytes());
    d[16..24].copy_from_slice(&wp.to_le_bytes());
    d[24] = ty;
    d[25] = state;
    d
}

fn report(descs: &[[u8; ZONE_DESCRIPTOR_BYTES]]) -> std::vec::Vec<u8> {
    let mut b = std::vec![0u8; ZONE_REPORT_HEADER_BYTES];
    b[0..8].copy_from_slice(&(descs.len() as u64).to_le_bytes());
    for d in descs { b.extend_from_slice(d); }
    b
}

#[test]
fn a_sequential_zone_decodes_its_pointer_and_short_capacity() {
    let b = report(&[descriptor(1000, 0, 384, VIRTIO_BLK_ZT_SWR, VIRTIO_BLK_ZS_IOPEN)]);
    assert_eq!(report_zone_count(&b), Some(1));
    let (z, len) = parse_zone(&b, 0, 1024, 8192).unwrap().unwrap();
    assert_eq!(z.start_sector, 0);
    assert_eq!(z.capacity_sectors, 1000);
    assert_eq!(z.write_pointer, Some(384));
    assert_eq!(z.kind, ZoneKind::SeqWriteRequired);
    assert_eq!(z.cond, ZoneCondition::ImplicitOpen);
    assert_eq!(len, 1024, "length comes from the zone size, not the short capacity");
}

/// A full zone's own pointer field is not meaningful; its END is where the
/// next write would have to go, and on the last, short zone that end is not
/// one zone size past the start.
#[test]
fn a_full_zone_reports_its_end_as_the_pointer() {
    let b = report(&[descriptor(1024, 1024, 0, VIRTIO_BLK_ZT_SWR, VIRTIO_BLK_ZS_FULL)]);
    let (z, len) = parse_zone(&b, 0, 1024, 2048).unwrap().unwrap();
    assert_eq!(len, 1024);
    assert_eq!(z.write_pointer, Some(2048));

    // Last zone, cut short by the drive's capacity.
    let b = report(&[descriptor(600, 1024, 0, VIRTIO_BLK_ZT_SWR, VIRTIO_BLK_ZS_FULL)]);
    let (z, len) = parse_zone(&b, 0, 1024, 1700).unwrap().unwrap();
    assert_eq!(len, 676, "the last zone is cut by the drive capacity");
    assert_eq!(z.write_pointer, Some(1700));
}

#[test]
fn a_conventional_zone_has_no_write_pointer() {
    let b = report(&[descriptor(1024, 0, 999, VIRTIO_BLK_ZT_CONV, VIRTIO_BLK_ZS_NOT_WP)]);
    let (z, _) = parse_zone(&b, 0, 1024, 4096).unwrap().unwrap();
    assert_eq!(z.kind, ZoneKind::Conventional);
    assert_eq!(z.write_pointer, None, "a conventional zone is writable anywhere");
}

/// Neither can be written, so neither has a place a write would go. Reporting
/// the device's stale pointer field for these would offer a legal-looking
/// target on a zone that refuses every write.
#[test]
fn read_only_and_offline_zones_have_no_write_pointer() {
    for state in [VIRTIO_BLK_ZS_RDONLY, VIRTIO_BLK_ZS_OFFLINE] {
        let b = report(&[descriptor(1024, 0, 512, VIRTIO_BLK_ZT_SWR, state)]);
        let (z, _) = parse_zone(&b, 0, 1024, 4096).unwrap().unwrap();
        assert_eq!(z.write_pointer, None, "state {state}");
    }
}

#[test]
fn every_defined_type_and_state_decodes() {
    let kinds = [(VIRTIO_BLK_ZT_CONV, ZoneKind::Conventional),
                 (VIRTIO_BLK_ZT_SWR, ZoneKind::SeqWriteRequired),
                 (VIRTIO_BLK_ZT_SWP, ZoneKind::SeqWritePreferred)];
    for (raw, want) in kinds {
        let b = report(&[descriptor(1024, 0, 0, raw, VIRTIO_BLK_ZS_EMPTY)]);
        assert_eq!(parse_zone(&b, 0, 1024, 4096).unwrap().unwrap().0.kind, want);
    }
    let states = [(VIRTIO_BLK_ZS_NOT_WP, ZoneCondition::NotWp),
                  (VIRTIO_BLK_ZS_EMPTY, ZoneCondition::Empty),
                  (VIRTIO_BLK_ZS_IOPEN, ZoneCondition::ImplicitOpen),
                  (VIRTIO_BLK_ZS_EOPEN, ZoneCondition::ExplicitOpen),
                  (VIRTIO_BLK_ZS_CLOSED, ZoneCondition::Closed),
                  (VIRTIO_BLK_ZS_RDONLY, ZoneCondition::ReadOnly),
                  (VIRTIO_BLK_ZS_FULL, ZoneCondition::Full),
                  (VIRTIO_BLK_ZS_OFFLINE, ZoneCondition::Offline)];
    for (raw, want) in states {
        let b = report(&[descriptor(1024, 0, 0, VIRTIO_BLK_ZT_SWR, raw)]);
        assert_eq!(parse_zone(&b, 0, 1024, 4096).unwrap().unwrap().0.cond, want, "state {raw}");
    }
}

/// A zone whose type or state is undefined has an unknown write rule. Guessing
/// one is how a sequential zone gets treated as conventional.
#[test]
fn an_undefined_type_or_state_is_an_error_not_a_default() {
    let b = report(&[descriptor(1024, 0, 0, 9, VIRTIO_BLK_ZS_EMPTY)]);
    assert_eq!(parse_zone(&b, 0, 1024, 4096).unwrap(), Err(ZoneParseError::UnknownType(9)));
    let b = report(&[descriptor(1024, 0, 0, VIRTIO_BLK_ZT_SWR, 7)]);
    assert_eq!(parse_zone(&b, 0, 1024, 4096).unwrap(), Err(ZoneParseError::UnknownState(7)));
}

#[test]
fn a_short_buffer_yields_no_zone_and_no_count() {
    assert_eq!(report_zone_count(&[0u8; 8]), None);
    let b = report(&[descriptor(1024, 0, 0, VIRTIO_BLK_ZT_SWR, VIRTIO_BLK_ZS_EMPTY)]);
    assert!(parse_zone(&b, 1, 1024, 4096).is_none(), "past the end of the buffer");
    assert_eq!(zones_per_buffer(ZONE_REPORT_HEADER_BYTES + 2 * ZONE_DESCRIPTOR_BYTES), 2);
    assert_eq!(zones_per_buffer(ZONE_REPORT_HEADER_BYTES), 0);
    assert_eq!(zones_per_buffer(8), 0);
}

/// A device is free to report FEWER zones than the buffer holds, and a driver
/// that walked the buffer instead of the header count would read zeros as a
/// conventional zone at sector 0 and overwrite its own map.
#[test]
fn the_header_count_bounds_the_walk_not_the_buffer_size() {
    let mut b = report(&[descriptor(1024, 0, 0, VIRTIO_BLK_ZT_SWR, VIRTIO_BLK_ZS_EMPTY)]);
    b.extend_from_slice(&[0u8; ZONE_DESCRIPTOR_BYTES]);
    assert_eq!(report_zone_count(&b), Some(1));
    assert_eq!(zones_per_buffer(b.len()), 2);
    // The trailing all-zero descriptor decodes as an undefined type, which is
    // exactly why the count, not the capacity, terminates the walk.
    assert_eq!(parse_zone(&b, 1, 1024, 4096).unwrap(), Err(ZoneParseError::UnknownType(0)));
}

#[test]
fn the_next_report_starts_one_zone_past_the_last_one_seen() {
    assert_eq!(next_report_sector(0, 1024), 1024);
    assert_eq!(next_report_sector(4096, 1024), 5120);
    assert_eq!(next_report_sector(u64::MAX, 1024), u64::MAX, "saturates, never wraps to 0");
}

// --- transfer bounding -----------------------------------------------------

/// A run that spans two sequential zones would put its tail at the head of a
/// zone whose write pointer is elsewhere. The chunk is cut at the boundary.
#[test]
fn a_transfer_is_cut_at_the_zone_boundary() {
    // 1024-sector zones, a 2000-sector run from 0: first chunk stops at 1024.
    assert_eq!(zone_bounded_chunk(0, 2000, 4096, 1024), Some(1024));
    // Resuming at the boundary takes the rest.
    assert_eq!(zone_bounded_chunk(1024, 976, 4096, 1024), Some(976));
    // Mid-zone start: only what is left of that zone.
    assert_eq!(zone_bounded_chunk(1500, 2000, 4096, 1024), Some(548));
}

#[test]
fn the_bounded_chunk_still_honours_the_bounce_window_and_the_remainder() {
    assert_eq!(zone_bounded_chunk(0, 2000, 256, 1024), Some(256), "bounce window wins");
    assert_eq!(zone_bounded_chunk(0, 100, 256, 1024), Some(100), "remainder wins");
    assert_eq!(zone_bounded_chunk(0, 0, 256, 1024), None);
    assert_eq!(zone_bounded_chunk(0, 100, 0, 1024), None);
}

/// A non-zoned drive has no boundary to cut at, and passing zero must not
/// divide or collapse the chunk to nothing.
#[test]
fn a_zero_zone_size_imposes_no_boundary() {
    assert_eq!(zone_bounded_chunk(1500, 2000, 4096, 0), Some(2000));
}

/// Repeated cutting must terminate and cover the run exactly once.
#[test]
fn cutting_a_long_run_covers_it_exactly() {
    let (mut at, mut left, mut total) = (777u64, 5000u64, 0u64);
    while let Some(n) = zone_bounded_chunk(at, left, 256, 1024) {
        assert!(n > 0);
        assert_eq!(at / 1024, (at + n - 1) / 1024, "chunk stayed inside one zone");
        at += n; left -= n; total += n;
        assert!(total <= 5000);
    }
    assert_eq!(total, 5000);
    assert_eq!(left, 0);
}

// --- command addressing + in-header ---------------------------------------

/// A management command names a zone by its FIRST sector; one pointing into
/// the middle of a zone is a driver bug, caught here rather than returned as
/// an opaque status byte.
#[test]
fn a_management_command_must_address_a_zone_start() {
    assert!(zone_command_aligned(VIRTIO_BLK_T_ZONE_OPEN, 0, 1024));
    assert!(zone_command_aligned(VIRTIO_BLK_T_ZONE_RESET, 4096, 1024));
    assert!(!zone_command_aligned(VIRTIO_BLK_T_ZONE_CLOSE, 1, 1024));
    assert!(!zone_command_aligned(VIRTIO_BLK_T_ZONE_FINISH, 1500, 1024));
    assert!(!zone_command_aligned(VIRTIO_BLK_T_ZONE_OPEN, 0, 0), "no zone size, no legal zone");
}

/// Reset-all addresses the whole drive, so its sector field is not a zone
/// start and must not be checked as one.
#[test]
fn reset_all_addresses_no_zone() {
    assert!(zone_command_aligned(VIRTIO_BLK_T_ZONE_RESET_ALL, 0, 1024));
    assert!(zone_command_aligned(VIRTIO_BLK_T_ZONE_RESET_ALL, 7, 0));
}

/// Zone append answers with the sector its data landed at ahead of the status
/// byte. A driver that reserved one byte would have the device write eight
/// bytes past the descriptor it declared.
#[test]
fn zone_append_has_a_wider_in_header_with_the_status_last() {
    assert_eq!(in_header_bytes(VIRTIO_BLK_T_ZONE_APPEND), 9);
    for t in [VIRTIO_BLK_T_ZONE_REPORT, VIRTIO_BLK_T_ZONE_OPEN, VIRTIO_BLK_T_ZONE_RESET,
              super::super::VIRTIO_BLK_T_IN, super::super::VIRTIO_BLK_T_OUT] {
        assert_eq!(in_header_bytes(t), 1, "type {t}");
    }

    let mut hdr = [0u8; ZONE_APPEND_IN_HEADER_BYTES];
    hdr[0..8].copy_from_slice(&4096u64.to_le_bytes());
    hdr[8] = super::super::VIRTIO_BLK_S_OK;
    assert_eq!(appended_sector(&hdr), Some(4096));
    assert_eq!(in_header_status(&hdr), Some(super::super::VIRTIO_BLK_S_OK));
    // One decode path serves both widths because the status is last.
    assert_eq!(in_header_status(&[VIRTIO_BLK_S_ZONE_UNALIGNED_WP]),
               Some(VIRTIO_BLK_S_ZONE_UNALIGNED_WP));
    assert_eq!(appended_sector(&[0u8; 8]), None);
    assert_eq!(in_header_status(&[]), None);
}

/// The zone statuses are distinct device answers. Collapsing them into one
/// I/O error is what makes an unaligned write — a placement mistake the
/// caller can correct — indistinguishable from media failure.
#[test]
fn zone_status_bytes_are_distinct_from_each_other_and_from_the_generic_ones() {
    let all = [super::super::VIRTIO_BLK_S_OK, super::super::VIRTIO_BLK_S_IOERR,
               super::super::VIRTIO_BLK_S_UNSUPP, VIRTIO_BLK_S_ZONE_INVALID_CMD,
               VIRTIO_BLK_S_ZONE_UNALIGNED_WP, VIRTIO_BLK_S_ZONE_OPEN_RESOURCE,
               VIRTIO_BLK_S_ZONE_ACTIVE_RESOURCE];
    for (i, a) in all.iter().enumerate() {
        for b in &all[i + 1..] { assert_ne!(a, b); }
    }
    assert_eq!(VIRTIO_BLK_S_ZONE_INVALID_CMD, 3);
    assert_eq!(VIRTIO_BLK_S_ZONE_UNALIGNED_WP, 4);
    assert_eq!(VIRTIO_BLK_S_ZONE_OPEN_RESOURCE, 5);
    assert_eq!(VIRTIO_BLK_S_ZONE_ACTIVE_RESOURCE, 6);
}

/// The wide in-header changes only the last descriptor's length, and only for
/// append. Every other chain keeps the one-byte status it had.
#[test]
fn the_wide_in_header_reaches_only_the_status_descriptor() {
    use super::super::{build_chain, build_chain_with_in_header};
    let (plain, n) = build_chain(false, 0x1000, 0x2000, 512, 0x3000);
    let (wide, wn) = build_chain_with_in_header(false, 0x1000, 0x2000, 512, 0x3000, 9);
    assert_eq!((n, wn), (3, 3));
    assert_eq!(plain[0], wide[0]);
    assert_eq!(plain[1], wide[1]);
    assert_eq!(plain[2].len, 1);
    assert_eq!(wide[2].len, 9);
    assert_eq!(plain[2].flags, wide[2].flags, "still device-writable, still the chain end");

    // A management command carries no data: header then the status alone.
    let (mgmt, mn) = build_chain_with_in_header(false, 0x1000, 0x2000, 0, 0x3000, 1);
    assert_eq!(mn, 2);
    assert_eq!(mgmt[1].addr, 0x3000);
    assert_eq!(mgmt[1].len, 1);
}
