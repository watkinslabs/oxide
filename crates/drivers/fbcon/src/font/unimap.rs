// Unicode-map ordering for the console font: sort by codepoint, keep the
// FIRST mapping of each, without the stable sort's scratch frame.

use alloc::vec::Vec;

/// Order `pairs` by codepoint and drop every repeat of one, keeping the
/// mapping that appeared FIRST in the input.
///
/// The obvious spelling — `sort_by_key` then `dedup_by_key` — relies on the
/// sort being stable, and `slice::sort_by_key` is `driftsort`: its ~4 KiB
/// scratch buffer is reserved in the CALLER's frame. That caller is the font
/// installer, which the console reaches lazily from a cell blit, which any
/// klog call can reach — so the scratch sat under console output on paths
/// already several KiB deep.
///
/// Carrying the input position in the key makes the order total, which is
/// exactly the property stability was providing, so an unstable sort produces
/// the identical result with no scratch at all.
/// # C: O(n log n)
pub(crate) fn sort_dedup_by_codepoint(pairs: &mut Vec<(u32, u16)>) {
    let mut keyed: Vec<(u32, u32, u16)> = Vec::new();
    keyed.reserve(pairs.len());
    for (position, &(codepoint, glyph)) in pairs.iter().enumerate() {
        keyed.push((codepoint, position as u32, glyph));
    }
    keyed.sort_unstable();
    keyed.dedup_by_key(|entry| entry.0);
    pairs.clear();
    for &(codepoint, _, glyph) in keyed.iter() { pairs.push((codepoint, glyph)); }
}

#[cfg(test)]
mod tests {
    use super::sort_dedup_by_codepoint;

    #[test]
    fn orders_by_codepoint() {
        let mut pairs = alloc::vec![(9u32, 90u16), (2, 20), (5, 50)];
        sort_dedup_by_codepoint(&mut pairs);
        assert_eq!(pairs, alloc::vec![(2, 20), (5, 50), (9, 90)]);
    }

    #[test]
    fn keeps_the_first_mapping_of_a_repeated_codepoint() {
        // The property the stable sort was there for: a unimap that maps one
        // codepoint twice resolves to the earlier entry, whatever the order
        // the sort happens to visit equal keys in.
        let mut pairs = alloc::vec![(7u32, 1u16), (3, 2), (7, 3), (3, 4), (7, 5)];
        sort_dedup_by_codepoint(&mut pairs);
        assert_eq!(pairs, alloc::vec![(3, 2), (7, 1)]);
    }

    #[test]
    fn empty_input_stays_empty() {
        let mut pairs: alloc::vec::Vec<(u32, u16)> = alloc::vec::Vec::new();
        sort_dedup_by_codepoint(&mut pairs);
        assert!(pairs.is_empty());
    }
}
