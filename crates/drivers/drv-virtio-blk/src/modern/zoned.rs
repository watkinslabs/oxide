// Zone commands on a host-managed virtio-blk drive: the report walk, the
// management transitions, and zone append.
//
// The unit boundary is the thing to keep straight. The drive addresses every
// zone command in 512-byte sectors; the `BlockDevice` surface above speaks
// this disk's own logical blocks. Every conversion is in one direction at one
// place here, and the arithmetic that decides it lives in `virtio::blk::zoned`
// where it is host-tested.

use super::*;
use block::zoned::{Zone, ZoneCond, ZoneMgmtOp, ZoneReport, ZoneType};
use virtio::blk::zoned as vz;

/// Zones asked for in one report request. The reply is a 64-byte header plus
/// 64 bytes per zone, so this run sits inside the engine's bounce window with
/// room to spare and keeps a whole-drive walk to a few requests.
const ZONES_PER_REQUEST: usize = 256;
const REPORT_BUFFER_BYTES: usize =
    vz::ZONE_REPORT_HEADER_BYTES + ZONES_PER_REQUEST * vz::ZONE_DESCRIPTOR_BYTES;

/// Map a device status byte to this layer's error, zone statuses included.
///
/// The two resource statuses are transient limits, not media failure: a
/// caller that closes or finishes a zone can reissue the same request and
/// succeed. Folding them into `Eio` is what turns a retryable placement
/// problem into an apparently broken drive. # C: O(1)
pub(super) fn zone_block_error(status: u8) -> BlockError {
    match status {
        blk::VIRTIO_BLK_S_UNSUPP => BlockError::Eopnotsupp,
        vz::VIRTIO_BLK_S_ZONE_INVALID_CMD => BlockError::Einval,
        // The write did not land where the drive's pointer is. The caller's
        // placement is stale, which a re-read of the zone report corrects.
        vz::VIRTIO_BLK_S_ZONE_UNALIGNED_WP => BlockError::Einval,
        vz::VIRTIO_BLK_S_ZONE_OPEN_RESOURCE => BlockError::Etoomanyrefs,
        vz::VIRTIO_BLK_S_ZONE_ACTIVE_RESOURCE => BlockError::Eoverflow,
        _ => BlockError::Eio,
    }
}

/// The virtio command for one management transition. # C: O(1)
fn mgmt_command(op: ZoneMgmtOp) -> u32 {
    match op {
        ZoneMgmtOp::Open => vz::VIRTIO_BLK_T_ZONE_OPEN,
        ZoneMgmtOp::Close => vz::VIRTIO_BLK_T_ZONE_CLOSE,
        ZoneMgmtOp::Finish => vz::VIRTIO_BLK_T_ZONE_FINISH,
        ZoneMgmtOp::Reset => vz::VIRTIO_BLK_T_ZONE_RESET,
        ZoneMgmtOp::ResetAll => vz::VIRTIO_BLK_T_ZONE_RESET_ALL,
    }
}

fn kind_of(k: vz::ZoneKind) -> ZoneType {
    match k {
        vz::ZoneKind::Conventional => ZoneType::Conventional,
        vz::ZoneKind::SeqWriteRequired => ZoneType::SeqWriteRequired,
        vz::ZoneKind::SeqWritePreferred => ZoneType::SeqWritePreferred,
    }
}

fn cond_of(c: vz::ZoneCondition) -> ZoneCond {
    match c {
        vz::ZoneCondition::NotWp => ZoneCond::NotWp,
        vz::ZoneCondition::Empty => ZoneCond::Empty,
        vz::ZoneCondition::ImplicitOpen => ZoneCond::ImplicitOpen,
        vz::ZoneCondition::ExplicitOpen => ZoneCond::ExplicitOpen,
        vz::ZoneCondition::Closed => ZoneCond::Closed,
        vz::ZoneCondition::ReadOnly => ZoneCond::ReadOnly,
        vz::ZoneCondition::Full => ZoneCond::Full,
        vz::ZoneCondition::Offline => ZoneCond::Offline,
    }
}

/// Append every zone one report reply describes to `out`, and answer with the
/// sector the next request must start at.
///
/// The walk is bounded by the count in the reply's HEADER, never by what the
/// buffer could hold: a device is free to answer with fewer zones than were
/// asked for, and decoding the untouched tail would read zeros as a
/// conventional zone at sector 0 and corrupt the map. `None` means the reply
/// was malformed — an undefined zone type or state, which has an unknown
/// write rule and must not be guessed at.
/// # C: O(zones in the reply)
fn absorb_report(
    buf: &[u8], info: &vz::ZonedInfo, device_sectors: u64, sectors_per_block: u64,
    out: &mut Vec<Zone>,
) -> Option<u64> {
    let reported = vz::report_zone_count(buf)?;
    let n = core::cmp::min(reported, vz::zones_per_buffer(buf.len()) as u64);
    let mut next = 0u64;
    for i in 0..n as usize {
        let (z, len_sectors) = vz::parse_zone(buf, i, info.zone_sectors, device_sectors)?.ok()?;
        out.push(Zone {
            start_block: z.start_sector / sectors_per_block,
            len_blocks: len_sectors / sectors_per_block,
            capacity_blocks: z.capacity_sectors / sectors_per_block,
            kind: kind_of(z.kind),
            wp_block: z.write_pointer.map(|w| w / sectors_per_block),
            cond: cond_of(z.cond),
        });
        next = vz::next_report_sector(z.start_sector, info.zone_sectors);
    }
    Some(next)
}

impl BlkState {
    /// Zone size in 512-byte sectors, or 0 on a drive with no zones — the
    /// "no boundary" input the chunk bound takes. # C: O(1)
    pub(super) fn zone_sectors(&self) -> u32 {
        self.zoned.map(|z| z.zone_sectors).unwrap_or(0)
    }

    /// Whether a sector run stays inside one zone. A run that leaves one is
    /// not refused — it is cut — but the asynchronous single-chain path
    /// cannot cut, so it declines the request here and lets the chunking path
    /// take it. # C: O(1)
    pub(super) fn run_within_one_zone(&self, base_sector: u64, sectors: u64) -> bool {
        let zs = self.zone_sectors();
        if zs == 0 || sectors == 0 { return true; }
        vz::zone_bounded_chunk(base_sector, sectors, sectors, zs) == Some(sectors)
    }

    /// Sectors of this drive per logical block. Never zero: `validate_blk_size`
    /// forced a multiple of 512. # C: O(1)
    fn sectors_per_block(&self) -> u64 {
        (self.blk_size as u64 / blk::VIRTIO_BLK_SECTOR_BYTES as u64).max(1)
    }

    fn sectors_to_blocks(&self, sectors: u64) -> u64 { sectors / self.sectors_per_block() }

    fn blocks_to_sectors(&self, blocks: u64) -> Option<u64> {
        blocks.checked_mul(self.sectors_per_block())
    }

    /// Walk the drive's whole zone map.
    ///
    /// One request per buffer-full, resuming where the last descriptor left
    /// off, until the drive's capacity is covered or a reply stops making
    /// progress. Everything the walk DECIDES — how far the reply is
    /// trustworthy, which unit each number is in — is in `absorb_report`,
    /// which is host-tested against synthetic replies.
    /// # C: O(zones)
    pub(super) fn read_zone_report(&self) -> Option<ZoneReport> {
        let info = self.zoned?;
        let spb = self.sectors_per_block();
        let mut buf = alloc::vec![0u8; REPORT_BUFFER_BYTES];
        let mut zones: Vec<Zone> = Vec::new();
        let mut sector: u64 = 0;

        while sector < self.capacity {
            for b in buf.iter_mut() { *b = 0; }
            self.submit(vz::VIRTIO_BLK_T_ZONE_REPORT, sector, &mut buf).ok()?;
            let next = absorb_report(&buf, &info, self.capacity, spb, &mut zones)?;
            // A reply that did not advance the cursor would loop forever on a
            // device that keeps answering with the same zone.
            if next <= sector { break; }
            sector = next;
        }

        if zones.is_empty() { return None; }
        Some(ZoneReport {
            zone_blocks: info.zone_sectors as u64 / spb,
            max_open_zones: info.open_limit(),
            max_active_zones: info.active_limit(),
            max_append_blocks: Some(info.max_append_sectors as u64 / spb).filter(|&b| b != 0),
            zones,
        })
    }

    /// Move one zone between states.
    ///
    /// A command that does not address a zone START is refused here rather
    /// than sent. The device would answer `S_ZONE_INVALID_CMD`, but a status
    /// byte at the far end does not say which caller got the address wrong,
    /// and rounding it to a boundary would reset a zone nobody named.
    /// # C: one request
    pub(super) fn issue_zone_mgmt(&self, op: ZoneMgmtOp, start_block: u64) -> KResult<()> {
        if self.zoned.is_none() { return Err(BlockError::Eopnotsupp); }
        let type_ = mgmt_command(op);
        let sector = if op == ZoneMgmtOp::ResetAll {
            0
        } else {
            self.blocks_to_sectors(start_block).ok_or(BlockError::Einval)?
        };
        if !vz::zone_command_aligned(type_, sector, self.zone_sectors()) {
            return Err(BlockError::Einval);
        }
        self.submit(type_, sector, &mut [])
    }

    /// Append to a sequential zone and report where the drive put the data.
    ///
    /// Nothing is split. An append is one placement, and the caller learns
    /// exactly one landing sector; issuing two requests for one buffer would
    /// place half the data somewhere the caller is never told about. A buffer
    /// past the drive's append limit is therefore refused, not chunked.
    /// # C: one request
    pub(super) fn issue_zone_append(&self, start_block: u64, buffer: &[u8]) -> KResult<u64> {
        let Some(info) = self.zoned else { return Err(BlockError::Eopnotsupp) };
        let bs = self.blk_size as usize;
        if buffer.is_empty() || buffer.len() % bs != 0 { return Err(BlockError::Einval); }
        let sector = self.blocks_to_sectors(start_block).ok_or(BlockError::Einval)?;
        if !vz::zone_command_aligned(vz::VIRTIO_BLK_T_ZONE_APPEND, sector, info.zone_sectors) {
            return Err(BlockError::Einval);
        }
        let sectors = (buffer.len() / blk::VIRTIO_BLK_SECTOR_BYTES as usize) as u64;
        if sectors > info.max_append_sectors as u64 { return Err(BlockError::Einval); }
        if buffer.len() > blk::BOUNCE_DATA_BYTES { return Err(BlockError::Einval); }

        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(buffer);
        let in_header = self.submit_in_header(vz::VIRTIO_BLK_T_ZONE_APPEND, sector, &mut data)?;
        let landed = vz::appended_sector(&in_header).ok_or(BlockError::Eio)?;
        Ok(self.sectors_to_blocks(landed))
    }
}

#[cfg(test)]
#[path = "zoned/tests.rs"]
mod tests;
