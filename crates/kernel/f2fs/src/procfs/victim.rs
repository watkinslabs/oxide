//! `victim_bits` — which sections the cleaner has already chosen.
//!
//! One digit per section, ten to a line, each line labelled with the number of
//! the section it starts at. A 1 says an ahead-of-demand search costed that
//! section and settled on it; a 0 says it did not, or that something has since
//! taken it or emptied it.
//!
//! The report is the only way to see the cleaner's memory from outside. Read
//! twice while the volume is under write pressure, it shows whether the
//! bounded search is sweeping the volume or sitting on one part of it — which
//! is the difference between a cleaner that keeps up and one that does not.

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;

use crate::fsattr::Attr;
use crate::mount::F2fs;

/// Sections per line.
const PER_LINE: u32 = 10;

/// The report, over `sections` sections of which `marked` are chosen.
/// # C: O(sections)
pub fn victim_bits_body(sections: u32, marked: &[u32]) -> String {
    let mut s = String::from("format: victim_secmap bitmaps\n");
    for i in 0..sections {
        if i % PER_LINE == 0 { s.push_str(&format!("{:<10}", i)); }
        s.push_str(if marked.contains(&i) { "1" } else { "0" });
        if i % PER_LINE == PER_LINE - 1 || i == sections - 1 { s.push('\n'); }
        else { s.push(' '); }
    }
    s
}

/// # C: O(sections)
pub(crate) fn file(fs: &Arc<F2fs>, dev: &str) -> Attr {
    let fs = Arc::clone(fs);
    Attr::ro(dev, "victim_bits", Arc::new(move || {
        let (n, marked) = {
            let v = fs.volume.lock();
            (v.section_count(), v.victim_sections())
        };
        Ok(victim_bits_body(n, &marked).into_bytes())
    }))
}
