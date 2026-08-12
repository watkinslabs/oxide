use super::*;

/// Opaque identity for one registered physical display aperture.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ApertureKey(u64);

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ApertureError { Inval, Busy }

pub type ApertureResult<T> = core::result::Result<T, ApertureError>;

#[derive(Copy, Clone)]
struct Aperture {
    key: ApertureKey,
    base: u64,
    end: u64,
    detach: fn(ApertureKey),
}

static APERTURES: Spinlock<Vec<Aperture>, DriverLockClass> = Spinlock::new(Vec::new());
static NEXT_KEY: AtomicU64 = AtomicU64::new(1);

fn end_of(base: u64, bytes: u64) -> Option<u64> { bytes.checked_sub(1)?.checked_add(base) }

fn overlaps(base: u64, end: u64, ap: Aperture) -> bool { base <= ap.end && ap.base <= end }

fn next_key() -> ApertureKey {
    loop {
        let raw = NEXT_KEY.fetch_add(1, Ordering::Relaxed);
        if raw != 0 { return ApertureKey(raw); }
    }
}

/// Claim a firmware framebuffer range until released or displaced by a native driver.
/// # C: O(N)
pub fn acquire_aperture(base: u64, bytes: u64, detach: fn(ApertureKey)) -> ApertureResult<ApertureKey> {
    let end = end_of(base, bytes).ok_or(ApertureError::Inval)?;
    let mut aps = APERTURES.lock();
    if aps.iter().copied().any(|ap| overlaps(base, end, ap)) { return Err(ApertureError::Busy); }
    let key = next_key();
    aps.push(Aperture { key, base, end, detach });
    Ok(key)
}

/// Release a firmware framebuffer claim during normal driver removal.
/// # C: O(N)
pub fn release_aperture(key: ApertureKey) -> bool {
    let mut aps = APERTURES.lock();
    let Some(pos) = aps.iter().position(|ap| ap.key == key) else { return false };
    aps.remove(pos);
    true
}

/// Detach every firmware framebuffer whose physical range overlaps `base..base+bytes`.
/// # C: O(N)
pub fn remove_conflicting_apertures(base: u64, bytes: u64) -> ApertureResult<usize> {
    let end = end_of(base, bytes).ok_or(ApertureError::Inval)?;
    let detached = {
        let mut aps = APERTURES.lock();
        let mut detached = Vec::new();
        let mut pos = 0;
        while pos < aps.len() {
            if overlaps(base, end, aps[pos]) { detached.push(aps.remove(pos)); } else { pos += 1; }
        }
        detached
    };
    for ap in detached.iter().copied() { (ap.detach)(ap.key); }
    Ok(detached.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static DETACHED: AtomicU64 = AtomicU64::new(0);

    fn detach(key: ApertureKey) { DETACHED.store(key.0, Ordering::Release); }

    fn reset() {
        APERTURES.lock().clear();
        DETACHED.store(0, Ordering::Release);
    }

    #[test]
    fn overlapping_claim_is_busy() {
        let _serial = TEST_LOCK.lock().unwrap();
        reset();
        let key = acquire_aperture(0x1000, 0x1000, detach).unwrap();
        assert_eq!(acquire_aperture(0x1800, 0x1000, detach), Err(ApertureError::Busy));
        assert!(release_aperture(key));
    }

    #[test]
    fn conflict_removal_unlinks_before_callback() {
        let _serial = TEST_LOCK.lock().unwrap();
        reset();
        let key = acquire_aperture(0x1000, 0x1000, detach).unwrap();
        assert_eq!(remove_conflicting_apertures(0x1800, 0x1000), Ok(1));
        assert_eq!(DETACHED.load(Ordering::Acquire), key.0);
        assert!(!release_aperture(key));
    }

    #[test]
    fn adjacent_ranges_do_not_conflict() {
        let _serial = TEST_LOCK.lock().unwrap();
        reset();
        let key = acquire_aperture(0x1000, 0x1000, detach).unwrap();
        assert_eq!(remove_conflicting_apertures(0x2000, 0x1000), Ok(0));
        assert!(release_aperture(key));
    }
}
