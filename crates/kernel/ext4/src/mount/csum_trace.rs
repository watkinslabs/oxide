//! One-shot origin record for an ext4 metadata checksum rejection.

#[cfg(feature = "debug-csum-origin")]
use core::sync::atomic::{AtomicBool, Ordering};

#[cfg(feature = "debug-csum-origin")]
static REPORTED: AtomicBool = AtomicBool::new(false);

/// Record the first rejected metadata checksum without changing its error flow.
/// # C: O(1)
pub(crate) fn first_csum_failure(site: &'static [u8], object: u64, block: u64) {
    #[cfg(feature = "debug-csum-origin")]
    {
        if REPORTED.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() { return; }
        klog::write_raw(b"[EXT4-CSUM-FIRST] site=");
        klog::write_raw(site);
        klog::write_raw(b" object=");
        klog::write_dec_u64(object);
        klog::write_raw(b" block=");
        klog::write_dec_u64(block);
        klog::write_raw(b"\n");
    }
    #[cfg(not(feature = "debug-csum-origin"))]
    let _ = (site, object, block);
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn first_reporter_claims_once() {
        let reported = AtomicBool::new(false);
        assert!(reported.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_ok());
        assert!(reported.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err());
    }
}
