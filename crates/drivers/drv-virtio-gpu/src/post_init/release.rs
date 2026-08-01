// DMA release policy for a removed scanout. Owned here rather than inline in
// `scanout.rs` so the decision is hosted-testable and stated in exactly one
// place for both the orderly-removal and failed-probe unwind paths.

/// PAs of a removed scanout's DMA frames that may be returned to the PMM.
///
/// Until the device is reset its resource table still names the framebuffer as
/// live backing store and the command frame as a descriptor target, and none of
/// the removal paths send DETACH_BACKING. Freeing either one then hands a
/// physical address the device may still write into back to the buddy allocator
/// — a free-while-DMA-live whose corrupting writes land on whatever the frame
/// is recycled into. `virtio::reset_device` is `#[must_use]` for this reason:
/// an UNCONFIRMED reset yields nothing to free, and the frames leak instead.
/// One leaked framebuffer on a failed teardown beats a live DMA target in the
/// heap.
/// # C: O(1)
pub(super) fn releasable_dma(
    reset_confirmed: bool, cmd_buf_pa: u64, fb_base_pa: u64,
) -> (Option<u64>, Option<u64>) {
    if !reset_confirmed {
        return (None, None);
    }
    (
        if cmd_buf_pa != 0 { Some(cmd_buf_pa) } else { None },
        if fb_base_pa != 0 { Some(fb_base_pa) } else { None },
    )
}

#[cfg(test)]
mod tests {
    use super::releasable_dma;

    const CMD_PA: u64 = 0x1000;
    const FB_PA: u64 = 0x20_0000;

    #[test]
    fn a_confirmed_reset_releases_both_frames() {
        assert_eq!(releasable_dma(true, CMD_PA, FB_PA), (Some(CMD_PA), Some(FB_PA)));
    }

    #[test]
    fn an_unconfirmed_reset_releases_nothing_so_the_device_keeps_its_frames() {
        assert_eq!(releasable_dma(false, CMD_PA, FB_PA), (None, None));
    }

    #[test]
    fn a_zero_pa_is_never_offered_for_release() {
        assert_eq!(releasable_dma(true, 0, 0), (None, None));
        assert_eq!(releasable_dma(true, 0, FB_PA), (None, Some(FB_PA)));
    }
}
