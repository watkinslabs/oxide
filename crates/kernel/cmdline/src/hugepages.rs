//! Linux HugeTLB early-boot parameters.

use crate::token;

/// The supported HugeTLB hstates and their requested persistent counts.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct HugepageRequest {
    pub huge_2m: Option<u64>,
    pub huge_1g: Option<u64>,
}

impl HugepageRequest {
    const fn empty() -> Self { Self { huge_2m: None, huge_1g: None } }
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum Size { Huge2M, Huge1G }

fn size(value: &[u8]) -> Option<Size> {
    let (n, used) = token::parse_uint(value);
    let suffix = &value[used..];
    let bytes = match suffix {
        b"" => n,
        b"K" | b"k" => n.checked_shl(10)?,
        b"M" | b"m" => n.checked_shl(20)?,
        b"G" | b"g" => n.checked_shl(30)?,
        _ => return None,
    };
    match bytes {
        2_097_152 => Some(Size::Huge2M),
        1_073_741_824 => Some(Size::Huge1G),
        _ => None,
    }
}

/// Parse a HugeTLB count. Node-qualified counts are accepted and summed,
/// because this kernel has no NUMA node allocator: the single pool is the
/// only valid destination for every node's requested pages.
fn count(value: &[u8]) -> Option<u64> {
    let mut total = 0u64;
    for part in value.split(|&c| c == b',') {
        let (node, rest) = match part.iter().position(|&c| c == b':') {
            Some(i) => (&part[..i], &part[i + 1..]),
            None => (&[][..], part),
        };
        if !node.is_empty() {
            let (n, used) = token::parse_uint(node);
            if used != node.len() { return None; }
            let _ = n;
        }
        let (n, used) = token::parse_uint(rest);
        if used != rest.len() { return None; }
        total = total.checked_add(n)?;
    }
    Some(total)
}

fn put(out: &mut HugepageRequest, which: Size, n: u64) -> bool {
    let slot = match which { Size::Huge2M => &mut out.huge_2m, Size::Huge1G => &mut out.huge_1g };
    if slot.is_some() { return false; }
    *slot = Some(n);
    true
}

/// Linux-shaped ordered parsing of `default_hugepagesz=`, `hugepagesz=` and
/// `hugepages=`. An invalid size makes the immediately associated count
/// inapplicable; a bare `hugepages=` selects the default hstate, and the
/// first implicit default request cannot be overwritten by a later pair.
pub fn hugepage_request(line: &[u8]) -> HugepageRequest {
    let mut out = HugepageRequest::empty();
    let mut default_size = Size::Huge2M;
    let mut default_seen = false;
    let mut implicit_default_used = false;
    let mut selected = None;
    let mut selected_valid = false;
    let mut selected_used = false;
    let mut selector_seen = false;

    for raw in token::tokens(line) {
        let (key, Some(value)) = token::split_token(raw) else { continue };
        match key {
            b"default_hugepagesz" if !default_seen => {
                if let Some(s) = size(value) { default_size = s; default_seen = true; }
            }
            b"hugepagesz" => {
                selector_seen = true;
                selected = size(value);
                selected_valid = selected.is_some();
                selected_used = false;
            }
            b"hugepages" => {
                let Some(n) = count(value) else { continue };
                let which = match selected {
                    Some(s) if selected_valid && !selected_used => { selected_used = true; s }
                    Some(_) => continue,
                    None if !selected_valid && selector_seen => continue,
                    None if !implicit_default_used => {
                        implicit_default_used = true;
                        default_size
                    }
                    None => continue,
                };
                let _ = put(&mut out, which, n);
            }
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairs_select_each_supported_hstate() {
        assert_eq!(hugepage_request(b"hugepagesz=2M hugepages=512 hugepagesz=1G hugepages=2"),
            HugepageRequest { huge_2m: Some(512), huge_1g: Some(2) });
    }

    #[test]
    fn bare_count_uses_the_default_and_cannot_be_overwritten() {
        assert_eq!(hugepage_request(b"hugepages=4 hugepagesz=2M hugepages=9"),
            HugepageRequest { huge_2m: Some(4), huge_1g: None });
    }

    #[test]
    fn invalid_size_invalidates_its_following_count() {
        assert_eq!(hugepage_request(b"hugepagesz=64K hugepages=8 hugepagesz=1G hugepages=1"),
            HugepageRequest { huge_2m: None, huge_1g: Some(1) });
    }

    #[test]
    fn node_counts_sum_into_the_single_pool() {
        assert_eq!(hugepage_request(b"hugepagesz=2M hugepages=0:1,1:2"),
            HugepageRequest { huge_2m: Some(3), huge_1g: None });
    }

    #[test]
    fn default_size_controls_a_bare_count() {
        assert_eq!(hugepage_request(b"default_hugepagesz=1G hugepages=2"),
            HugepageRequest { huge_2m: None, huge_1g: Some(2) });
    }
}
