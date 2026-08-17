use super::*;

/// The device-written in-header a completed request left behind, padded to
/// the widest form. Its LAST meaningful byte is the status; zone append
/// prefixes the sector its data landed at.
pub(super) type InHeader = [u8; VIRTIO_BLK_MAX_IN_HEADER_BYTES];

/// Request types whose data descriptor the DEVICE writes.
///
/// Getting this wrong does not fail loudly: a device-readable descriptor on a
/// reply leaves the driver reading its own zeros, which for a zone report
/// decodes as a drive with no zones at all. # C: O(1)
pub(super) fn device_writes_data(type_: u32) -> bool {
    matches!(type_,
        blk::VIRTIO_BLK_T_IN
        | blk::VIRTIO_BLK_T_GET_ID
        | virtio::blk::zoned::VIRTIO_BLK_T_ZONE_REPORT)
}

impl BlkState {
    pub(super) fn submit(&self, type_: u32, sector: u64, data: &mut [u8]) -> KResult<()> {
        self.submit_in_header(type_, sector, data).map(|_| ())
    }

    /// `submit`, keeping the device's in-header. Only zone append has
    /// anything in it beyond the status byte the caller already sees as an
    /// error or its absence.
    pub(super) fn submit_in_header(&self, type_: u32, sector: u64, data: &mut [u8]) -> KResult<InHeader> {
        if self.poisoned.load(core::sync::atomic::Ordering::Acquire) {
            #[cfg(feature = "debug-boot")]
            log_submit_failure(b"poisoned-pre", type_, sector, data.len() as u32, BlockError::Eio);
            return Err(BlockError::Eio);
        }
        let h = hhdm();
        if h == 0 || !self.requestq.res.is_runtime_valid() || self.bounce_pa == 0 {
            #[cfg(feature = "debug-boot")]
            log_submit_failure(b"invalid-runtime", type_, sector, data.len() as u32, BlockError::Eio);
            return Err(BlockError::Eio);
        }
        let is_flush = type_ == blk::VIRTIO_BLK_T_FLUSH;
        let is_in = device_writes_data(type_);
        let data_len: u32 = if is_flush { 0 } else { data.len() as u32 };
        if data_len as usize > blk::BOUNCE_DATA_BYTES { return Err(BlockError::Einval); }
        self.acquire_turn();
        if self.poisoned.load(core::sync::atomic::Ordering::Acquire) {
            self.release_turn();
            #[cfg(feature = "debug-boot")]
            log_submit_failure(b"poisoned-turn", type_, sector, data_len, BlockError::Eio);
            return Err(BlockError::Eio);
        }
        let result = self.do_request(h, type_, sector, data, is_in, is_flush, data_len);
        #[cfg(feature = "debug-boot")]
        if let Err(error) = result { log_submit_failure(b"request", type_, sector, data_len, error); }
        if matches!(result, Err(BlockError::Eio)) && self.poisoned.load(core::sync::atomic::Ordering::Acquire) {
            // Poisoned abort: returns WITHOUT release_turn, so every sleeper on
            // either condition must be roused to re-check and bail.
            #[cfg(target_os = "oxide-kernel")]
            wake_all_blk_waiters();
            return result;
        }
        self.release_turn();
        result
    }
}
