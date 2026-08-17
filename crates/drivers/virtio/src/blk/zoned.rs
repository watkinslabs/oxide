// Zoned virtio-blk wire shapes + the probe decision, per Virtio 1.2's zoned
// block-device appendix. Pure data and arithmetic: no MMIO, no HHDM, no
// allocation of device memory. The engine in `drv-virtio-blk` consumes these
// to issue the zone commands and to decide whether a zoned device may be
// attached at all.
//
// The whole point of keeping this here is that the DECISIONS are host-tested.
// Which model is attachable, which characteristics make a device unusable,
// how a descriptor's type/state byte maps to a zone kind, where a transfer
// must be cut so it cannot cross a zone boundary — each is a place where a
// wrong answer writes behind a drive's write pointer, and each is exercised
// in `cargo test` without a boot.

/// Zoned block device (feature bit 17).
pub const VIRTIO_BLK_F_ZONED: u64 = 1 << 17;

/// Zone commands. `RESET_ALL` addresses the whole drive and ignores its
/// sector field; every other command addresses one zone by its start sector.
pub const VIRTIO_BLK_T_ZONE_APPEND:    u32 = 15;
pub const VIRTIO_BLK_T_ZONE_REPORT:    u32 = 16;
pub const VIRTIO_BLK_T_ZONE_OPEN:      u32 = 18;
pub const VIRTIO_BLK_T_ZONE_CLOSE:     u32 = 20;
pub const VIRTIO_BLK_T_ZONE_FINISH:    u32 = 22;
pub const VIRTIO_BLK_T_ZONE_RESET:     u32 = 24;
pub const VIRTIO_BLK_T_ZONE_RESET_ALL: u32 = 26;

/// Zone-specific status bytes. They are NOT interchangeable with `S_IOERR`:
/// an unaligned write pointer is a placement mistake the caller can correct,
/// and the two resource statuses are transient limits, not media failure.
pub const VIRTIO_BLK_S_ZONE_INVALID_CMD:     u8 = 3;
pub const VIRTIO_BLK_S_ZONE_UNALIGNED_WP:    u8 = 4;
pub const VIRTIO_BLK_S_ZONE_OPEN_RESOURCE:   u8 = 5;
pub const VIRTIO_BLK_S_ZONE_ACTIVE_RESOURCE: u8 = 6;

/// Device models in the zoned characteristics block.
pub const VIRTIO_BLK_Z_NONE: u8 = 0;
pub const VIRTIO_BLK_Z_HM:   u8 = 1;
pub const VIRTIO_BLK_Z_HA:   u8 = 2;

/// Zone types in a report descriptor.
pub const VIRTIO_BLK_ZT_CONV: u8 = 1;
pub const VIRTIO_BLK_ZT_SWR:  u8 = 2;
pub const VIRTIO_BLK_ZT_SWP:  u8 = 3;

/// Zone states in a report descriptor.
pub const VIRTIO_BLK_ZS_NOT_WP:  u8 = 0;
pub const VIRTIO_BLK_ZS_EMPTY:   u8 = 1;
pub const VIRTIO_BLK_ZS_IOPEN:   u8 = 2;
pub const VIRTIO_BLK_ZS_EOPEN:   u8 = 3;
pub const VIRTIO_BLK_ZS_CLOSED:  u8 = 4;
pub const VIRTIO_BLK_ZS_RDONLY:  u8 = 13;
pub const VIRTIO_BLK_ZS_FULL:    u8 = 14;
pub const VIRTIO_BLK_ZS_OFFLINE: u8 = 15;

/// `virtio_blk_config.zoned` byte offsets. The characteristics block follows
/// the secure-erase entries, so it starts at 72 in the packed config.
pub const BLK_CFG_OFF_ZONE_SECTORS:      u64 = 72;
pub const BLK_CFG_OFF_MAX_OPEN_ZONES:    u64 = 76;
pub const BLK_CFG_OFF_MAX_ACTIVE_ZONES:  u64 = 80;
pub const BLK_CFG_OFF_MAX_APPEND_SECTORS: u64 = 84;
pub const BLK_CFG_OFF_WRITE_GRANULARITY: u64 = 88;
pub const BLK_CFG_OFF_ZONE_MODEL:        u64 = 92;
/// Bytes of the config the characteristics block spans, from `ZONE_SECTORS`
/// through `model`. Read as one run so the fields cannot be sampled at
/// different times.
pub const BLK_CFG_ZONED_BYTES: usize = 21;

/// `virtio_blk_zone_report`: an le64 count then 56 reserved bytes.
pub const ZONE_REPORT_HEADER_BYTES: usize = 64;
/// `virtio_blk_zone_descriptor`: cap, start, wp, type, state, 38 reserved.
pub const ZONE_DESCRIPTOR_BYTES: usize = 64;
const ZD_OFF_CAP: usize = 0;
const ZD_OFF_START: usize = 8;
const ZD_OFF_WP: usize = 16;
const ZD_OFF_TYPE: usize = 24;
const ZD_OFF_STATE: usize = 25;

/// Virtio addresses every zone command in 512-byte sectors, as it does reads
/// and writes.
const SECTOR_SHIFT: u32 = 9;

/// What a device's zoned characteristics say the driver may do with it.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ZonedInfo {
    /// Uniform zone size, in 512-byte sectors. A power of two.
    pub zone_sectors: u32,
    /// Zones the drive keeps explicitly open at once; 0 means unlimited.
    pub max_open_zones: u32,
    /// Zones the drive keeps active at once; 0 means unlimited.
    pub max_active_zones: u32,
    /// Largest zone-append transfer, in 512-byte sectors. Never zero.
    pub max_append_sectors: u32,
    /// Smallest write the drive accepts, in bytes. Never zero.
    pub write_granularity: u32,
}

impl ZonedInfo {
    /// A stated limit, or `None` when the drive states none. Zero in the
    /// config is "no limit", not "no zones may be open" — reading it as a
    /// number would make every open refuse. # C: O(1)
    pub fn open_limit(&self) -> Option<u32> {
        if self.max_open_zones == 0 { None } else { Some(self.max_open_zones) }
    }

    /// # C: O(1)
    pub fn active_limit(&self) -> Option<u32> {
        if self.max_active_zones == 0 { None } else { Some(self.max_active_zones) }
    }
}

/// Why a device that claims zones cannot be attached. Each is a refusal, not
/// a downgrade: attaching the drive as if it were flat would let a filesystem
/// place blocks the drive will reject or relocate.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ZonedRefusal {
    /// A model byte outside the three the specification defines.
    UnknownModel(u8),
    /// A drive that will not say how small a write it accepts.
    ZeroWriteGranularity,
    /// Zone size of zero, or one this driver's addressing cannot index.
    ZoneSectorsNotPowerOfTwo(u32),
    /// A drive that admits no append at all, while requiring appends.
    ZeroMaxAppendSectors,
    /// An append limit below one write unit: no legal append exists.
    AppendBelowWriteGranularity { write_granularity: u32, max_append_sectors: u32 },
    /// A zone that is not a whole number of this disk's logical blocks. Every
    /// zone boundary would then fall inside a block, so no block-addressed
    /// caller could place a write at a zone start.
    ZoneSizeNotBlockAligned { zone_sectors: u32, blk_size: u32 },
}

/// The probe answer for one device.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ZonedProbe {
    /// Treat as an ordinary drive. Host-aware drives land here: they accept
    /// any write order, so nothing above needs a zone map to be correct.
    NotZoned,
    /// A host-managed drive whose characteristics this driver can honour.
    HostManaged(ZonedInfo),
    /// A drive that must not be attached.
    Refuse(ZonedRefusal),
}

/// Decide what to do with a device that offered `VIRTIO_BLK_F_ZONED`, from
/// the `BLK_CFG_ZONED_BYTES` run starting at `BLK_CFG_OFF_ZONE_SECTORS`.
///
/// The refusal order is the reference's and is load-bearing: a drive with
/// both a zero write granularity and a bad zone size is refused for the
/// granularity, so the diagnostic names the first thing wrong rather than
/// whichever check happened to run first.
/// # C: O(1)
pub fn probe_zoned(cfg: &[u8]) -> ZonedProbe {
    if cfg.len() < BLK_CFG_ZONED_BYTES { return ZonedProbe::NotZoned; }
    let at32 = |off: u64| -> u32 {
        let i = (off - BLK_CFG_OFF_ZONE_SECTORS) as usize;
        u32::from_le_bytes([cfg[i], cfg[i + 1], cfg[i + 2], cfg[i + 3]])
    };
    let model = cfg[(BLK_CFG_OFF_ZONE_MODEL - BLK_CFG_OFF_ZONE_SECTORS) as usize];
    match model {
        VIRTIO_BLK_Z_NONE | VIRTIO_BLK_Z_HA => return ZonedProbe::NotZoned,
        VIRTIO_BLK_Z_HM => {}
        other => return ZonedProbe::Refuse(ZonedRefusal::UnknownModel(other)),
    }

    let max_open_zones = at32(BLK_CFG_OFF_MAX_OPEN_ZONES);
    let max_active_zones = at32(BLK_CFG_OFF_MAX_ACTIVE_ZONES);

    let write_granularity = at32(BLK_CFG_OFF_WRITE_GRANULARITY);
    if write_granularity == 0 { return ZonedProbe::Refuse(ZonedRefusal::ZeroWriteGranularity); }

    let zone_sectors = at32(BLK_CFG_OFF_ZONE_SECTORS);
    if zone_sectors == 0 || !zone_sectors.is_power_of_two() {
        return ZonedProbe::Refuse(ZonedRefusal::ZoneSectorsNotPowerOfTwo(zone_sectors));
    }

    let max_append_sectors = at32(BLK_CFG_OFF_MAX_APPEND_SECTORS);
    if max_append_sectors == 0 { return ZonedProbe::Refuse(ZonedRefusal::ZeroMaxAppendSectors); }
    if ((max_append_sectors as u64) << SECTOR_SHIFT) < write_granularity as u64 {
        return ZonedProbe::Refuse(
            ZonedRefusal::AppendBelowWriteGranularity { write_granularity, max_append_sectors });
    }

    ZonedProbe::HostManaged(ZonedInfo {
        zone_sectors, max_open_zones, max_active_zones, max_append_sectors, write_granularity,
    })
}

/// Whether a zone is a whole number of `blk_size` logical blocks.
///
/// Checked separately from [`probe_zoned`] because it pairs the zoned
/// characteristics with the logical block size, which is a different part of
/// the config and is validated on its own first.
/// # C: O(1)
pub fn zone_size_block_aligned(zone_sectors: u32, blk_size: u32) -> bool {
    if blk_size == 0 { return false; }
    let bytes = (zone_sectors as u64) << SECTOR_SHIFT;
    bytes != 0 && bytes % blk_size as u64 == 0
}

/// One zone as the device described it, in 512-byte sectors.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ZoneDescriptor {
    pub start_sector: u64,
    pub capacity_sectors: u64,
    /// Where the next sequential write must land. A full zone's pointer is
    /// its end; a read-only or offline zone has none.
    pub write_pointer: Option<u64>,
    pub kind: ZoneKind,
    pub cond: ZoneCondition,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ZoneKind { Conventional, SeqWriteRequired, SeqWritePreferred }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ZoneCondition { NotWp, Empty, ImplicitOpen, ExplicitOpen, Closed, ReadOnly, Full, Offline }

/// A descriptor byte the specification does not define. Refused rather than
/// guessed: a zone whose type is unknown has an unknown write rule.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ZoneParseError { UnknownType(u8), UnknownState(u8) }

/// Zones a buffer of `bytes` can hold after its report header.
/// # C: O(1)
pub fn zones_per_buffer(bytes: usize) -> usize {
    bytes.saturating_sub(ZONE_REPORT_HEADER_BYTES) / ZONE_DESCRIPTOR_BYTES
}

/// The zone count the device wrote into the report header, or `None` when
/// the buffer is too short to hold a header at all.
/// # C: O(1)
pub fn report_zone_count(buf: &[u8]) -> Option<u64> {
    if buf.len() < ZONE_REPORT_HEADER_BYTES { return None; }
    Some(u64::from_le_bytes(buf[0..8].try_into().ok()?))
}

/// Decode the `idx`-th descriptor of a report buffer.
///
/// `zone_sectors` and `capacity_sectors` fix the zone's LENGTH, which the
/// descriptor does not carry: a zone is one zone-size long unless it is the
/// last one on the drive, where the drive's capacity cuts it short. Getting
/// this from the descriptor's own capacity instead would be wrong whenever a
/// zone has a short capacity, which is the case the whole type exists for.
/// # C: O(1)
pub fn parse_zone(
    buf: &[u8], idx: usize, zone_sectors: u32, device_sectors: u64,
) -> Option<Result<(ZoneDescriptor, u64), ZoneParseError>> {
    let off = ZONE_REPORT_HEADER_BYTES.checked_add(idx.checked_mul(ZONE_DESCRIPTOR_BYTES)?)?;
    let d = buf.get(off..off + ZONE_DESCRIPTOR_BYTES)?;
    let le64 = |o: usize| u64::from_le_bytes(d[o..o + 8].try_into().unwrap());
    let capacity_sectors = le64(ZD_OFF_CAP);
    let start_sector = le64(ZD_OFF_START);
    let raw_wp = le64(ZD_OFF_WP);

    let kind = match d[ZD_OFF_TYPE] {
        VIRTIO_BLK_ZT_CONV => ZoneKind::Conventional,
        VIRTIO_BLK_ZT_SWR  => ZoneKind::SeqWriteRequired,
        VIRTIO_BLK_ZT_SWP  => ZoneKind::SeqWritePreferred,
        other => return Some(Err(ZoneParseError::UnknownType(other))),
    };

    // Length first: the FULL state below reports the pointer as the zone's
    // end, which is a different sector on the last, short zone.
    let len_sectors = match start_sector.checked_add(zone_sectors as u64) {
        Some(end) if end <= device_sectors => zone_sectors as u64,
        _ => device_sectors.saturating_sub(start_sector),
    };

    let cond = match d[ZD_OFF_STATE] {
        VIRTIO_BLK_ZS_EMPTY   => ZoneCondition::Empty,
        VIRTIO_BLK_ZS_CLOSED  => ZoneCondition::Closed,
        VIRTIO_BLK_ZS_FULL    => ZoneCondition::Full,
        VIRTIO_BLK_ZS_EOPEN   => ZoneCondition::ExplicitOpen,
        VIRTIO_BLK_ZS_IOPEN   => ZoneCondition::ImplicitOpen,
        VIRTIO_BLK_ZS_NOT_WP  => ZoneCondition::NotWp,
        VIRTIO_BLK_ZS_RDONLY  => ZoneCondition::ReadOnly,
        VIRTIO_BLK_ZS_OFFLINE => ZoneCondition::Offline,
        other => return Some(Err(ZoneParseError::UnknownState(other))),
    };

    let write_pointer = match cond {
        // A full zone's own pointer field is not meaningful; its end is.
        ZoneCondition::Full => Some(start_sector.saturating_add(len_sectors)),
        // Neither can be written, so neither has a place a write would go.
        ZoneCondition::ReadOnly | ZoneCondition::Offline => None,
        // A conventional zone is writable anywhere, so it has no pointer.
        _ if kind == ZoneKind::Conventional => None,
        _ => Some(raw_wp),
    };

    Some(Ok((
        ZoneDescriptor { start_sector, capacity_sectors, write_pointer, kind, cond },
        len_sectors,
    )))
}

/// Where the next report request must start, given the descriptor just
/// consumed: one zone size past that zone's start, never past the drive.
/// # C: O(1)
pub fn next_report_sector(zone_start: u64, zone_sectors: u32) -> u64 {
    zone_start.saturating_add(zone_sectors as u64)
}

/// Cut a transfer so it cannot cross a zone boundary.
///
/// A drive is addressed by one sector run per request, and a run that spans
/// two sequential zones would put its tail at the head of a zone whose write
/// pointer is elsewhere. The reference expresses this as a queue-limit the
/// block layer splits on; with no splitter above, the cut happens here, and
/// it is a cut rather than a refusal because a caller writing a legal
/// multi-zone run has done nothing wrong.
///
/// Returns the sectors this chunk may carry: at most `max`, at most what is
/// left, and never past the end of the zone `base_sector` is in. `None` once
/// the run is done or the inputs cannot describe one.
/// # C: O(1)
pub fn zone_bounded_chunk(base_sector: u64, remaining: u64, max: u64, zone_sectors: u32) -> Option<u64> {
    if max == 0 || remaining == 0 { return None; }
    let mut n = core::cmp::min(max, remaining);
    if zone_sectors != 0 {
        let zs = zone_sectors as u64;
        let to_boundary = zs - (base_sector % zs);
        n = core::cmp::min(n, to_boundary);
    }
    if n == 0 { None } else { Some(n) }
}

/// Whether a zone command addresses a legal zone start.
///
/// A management command names a zone by its FIRST sector. Sending one that
/// points into the middle of a zone is a driver bug the device answers with
/// an invalid-command status, so it is caught here instead — the failure is
/// then attributable, rather than an opaque status byte at the far end.
/// `RESET_ALL` addresses no zone and is exempt.
/// # C: O(1)
pub fn zone_command_aligned(type_: u32, sector: u64, zone_sectors: u32) -> bool {
    if type_ == VIRTIO_BLK_T_ZONE_RESET_ALL { return true; }
    zone_sectors != 0 && sector % zone_sectors as u64 == 0
}

/// The in-header a request type expects. Zone append answers with the sector
/// its data landed at ahead of the status byte, so its status descriptor is
/// wider — and the status is the LAST byte of it either way, which is what
/// lets one decode path serve both.
/// # C: O(1)
pub fn in_header_bytes(type_: u32) -> usize {
    if type_ == VIRTIO_BLK_T_ZONE_APPEND { ZONE_APPEND_IN_HEADER_BYTES } else { 1 }
}

/// le64 appended-at sector, then the status byte.
pub const ZONE_APPEND_IN_HEADER_BYTES: usize = 9;

/// The sector a completed zone append reported, from its in-header.
/// # C: O(1)
pub fn appended_sector(in_header: &[u8]) -> Option<u64> {
    if in_header.len() < ZONE_APPEND_IN_HEADER_BYTES { return None; }
    Some(u64::from_le_bytes(in_header[0..8].try_into().ok()?))
}

/// The status byte of an in-header of any width: always its last byte.
/// # C: O(1)
pub fn in_header_status(in_header: &[u8]) -> Option<u8> { in_header.last().copied() }

#[cfg(test)]
#[path = "zoned/tests.rs"]
mod tests;
