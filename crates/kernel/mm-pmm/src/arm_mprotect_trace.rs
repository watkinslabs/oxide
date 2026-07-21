use core::sync::atomic::{AtomicU64, Ordering};

static CALLS: AtomicU64 = AtomicU64::new(0);
static SCANNED: AtomicU64 = AtomicU64::new(0);
static PRESENT: AtomicU64 = AtomicU64::new(0);
static REPLACED: AtomicU64 = AtomicU64::new(0);
static COW_WRITE_HELD: AtomicU64 = AtomicU64::new(0);

#[derive(Default)]
pub(crate) struct ArmMprotectProgress {
    pub(crate) scanned: usize,
    pub(crate) present: usize,
    pub(crate) replaced: usize,
    pub(crate) cow_write_held: usize,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct ArmMprotectTotals {
    pub(crate) calls: u64,
    pub(crate) scanned: u64,
    pub(crate) present: u64,
    pub(crate) replaced: u64,
    pub(crate) cow_write_held: u64,
}

impl ArmMprotectTotals {
    pub(crate) fn absent(self) -> u64 { self.scanned.saturating_sub(self.present) }
}

impl ArmMprotectProgress {
    pub(crate) fn scan(&mut self) { self.scanned += 1; }
    pub(crate) fn present(&mut self) { self.present += 1; }
    pub(crate) fn replaced(&mut self) { self.replaced += 1; }
    pub(crate) fn cow_write_held(&mut self) { self.cow_write_held += 1; }
    pub(crate) fn absent(&self) -> usize { self.scanned.saturating_sub(self.present) }
}

pub(crate) fn record(progress: &ArmMprotectProgress) {
    CALLS.fetch_add(1, Ordering::Relaxed);
    SCANNED.fetch_add(progress.scanned as u64, Ordering::Relaxed);
    PRESENT.fetch_add(progress.present as u64, Ordering::Relaxed);
    REPLACED.fetch_add(progress.replaced as u64, Ordering::Relaxed);
    COW_WRITE_HELD.fetch_add(progress.cow_write_held as u64, Ordering::Relaxed);
}

pub(crate) fn totals() -> ArmMprotectTotals {
    ArmMprotectTotals {
        calls: CALLS.load(Ordering::Relaxed),
        scanned: SCANNED.load(Ordering::Relaxed),
        present: PRESENT.load(Ordering::Relaxed),
        replaced: REPLACED.load(Ordering::Relaxed),
        cow_write_held: COW_WRITE_HELD.load(Ordering::Relaxed),
    }
}

pub(crate) fn totals_with(progress: &ArmMprotectProgress) -> ArmMprotectTotals {
    let mut totals = totals();
    totals.calls += 1;
    totals.scanned += progress.scanned as u64;
    totals.present += progress.present as u64;
    totals.replaced += progress.replaced as u64;
    totals.cow_write_held += progress.cow_write_held as u64;
    totals
}

#[cfg(target_os = "oxide-kernel")]
pub(crate) fn checkpoint(retired_root: u64) {
    let totals = totals();
    klog::write_raw(b"[ARM-MPROTECT] checkpoint retired-root="); klog::write_hex_u64(retired_root);
    klog::write_raw(b" calls="); klog::write_dec_u64(totals.calls);
    klog::write_raw(b" scanned="); klog::write_dec_u64(totals.scanned);
    klog::write_raw(b" present="); klog::write_dec_u64(totals.present);
    klog::write_raw(b" replaced="); klog::write_dec_u64(totals.replaced);
    klog::write_raw(b" cow-write-held="); klog::write_dec_u64(totals.cow_write_held);
    klog::write_raw(b" absent="); klog::write_dec_u64(totals.absent());
    klog::write_raw(b"\n");
}

#[cfg(test)]
mod tests {
    use super::ArmMprotectProgress;

    #[test]
    fn counts_exact_mprotect_progress() {
        let mut trace = ArmMprotectProgress::default();
        let pages = ["cow", "plain", "absent"];
        for page in pages {
            trace.scan();
            if page == "absent" { continue; }
            trace.present();
            if page == "cow" { trace.cow_write_held(); }
            trace.replaced();
        }
        assert_eq!(trace.scanned, pages.len());
        assert_eq!(trace.present, ["cow", "plain"].len());
        assert_eq!(trace.replaced, ["cow", "plain"].len());
        assert_eq!(trace.cow_write_held, ["cow"].len());
        assert_eq!(trace.absent(), ["absent"].len());
    }

    #[test]
    fn aggregates_exact_mprotect_progress() {
        let before = super::totals();
        let mut trace = ArmMprotectProgress::default();
        for page in ["cow", "plain", "absent"] {
            trace.scan();
            if page == "absent" { continue; }
            trace.present();
            if page == "cow" { trace.cow_write_held(); }
            trace.replaced();
        }
        super::record(&trace);
        let after = super::totals();
        assert_eq!(after.calls - before.calls, ["call"].len() as u64);
        assert_eq!(after.scanned - before.scanned, ["cow", "plain", "absent"].len() as u64);
        assert_eq!(after.present - before.present, ["cow", "plain"].len() as u64);
        assert_eq!(after.replaced - before.replaced, ["cow", "plain"].len() as u64);
        assert_eq!(after.cow_write_held - before.cow_write_held, ["cow"].len() as u64);
        assert_eq!(after.absent() - before.absent(), ["absent"].len() as u64);
    }
}
