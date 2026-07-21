#[derive(Default)]
pub(crate) struct ArmMprotectProgress {
    pub(crate) scanned: usize,
    pub(crate) present: usize,
    pub(crate) replaced: usize,
    pub(crate) cow_write_held: usize,
}

impl ArmMprotectProgress {
    pub(crate) fn scan(&mut self) { self.scanned += 1; }
    pub(crate) fn present(&mut self) { self.present += 1; }
    pub(crate) fn replaced(&mut self) { self.replaced += 1; }
    pub(crate) fn cow_write_held(&mut self) { self.cow_write_held += 1; }
    pub(crate) fn absent(&self) -> usize { self.scanned.saturating_sub(self.present) }
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
}
