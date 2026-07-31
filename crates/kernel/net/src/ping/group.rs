// `net.ipv4.ping_group_range` — the group window that decides which callers may
// open an ICMP datagram endpoint. Ungated so the parse/format/admission
// contract is covered by `cargo test -p net` on the host.

use core::sync::atomic::{AtomicU64, Ordering};

/// Highest value the leaf accepts before the group identity itself is rejected;
/// `(gid_t)-1` is the reserved invalid group and never names a real group.
pub const GID_MAX: u64 = u32::MAX as u64;
pub const INVALID_GID: u32 = u32::MAX;

/// The disabled window: no group id satisfies `low <= gid <= high`.
pub const DISABLED_LOW: u32 = 1;
pub const DISABLED_HIGH: u32 = 0;

/// Per-network-namespace group window, published as one word so a reader can
/// never observe a half-updated pair.
pub struct GroupRange { packed: AtomicU64 }

const fn pack(low: u32, high: u32) -> u64 { (low as u64) << 32 | high as u64 }

impl GroupRange {
    /// The compiled default window, which admits nobody. # C: O(1)
    pub const fn new() -> Self { Self { packed: AtomicU64::new(pack(DISABLED_LOW, DISABLED_HIGH)) } }

    /// Snapshot the coherent `(low, high)` pair. # C: O(1)
    pub fn get(&self) -> (u32, u32) {
        let raw = self.packed.load(Ordering::Acquire);
        ((raw >> 32) as u32, raw as u32)
    }

    /// Publish a validated pair. # C: O(1)
    pub fn set(&self, low: u32, high: u32) {
        self.packed.store(pack(low, high), Ordering::Release);
    }

    /// Whether one group id falls inside the window. # C: O(1)
    pub fn contains(&self, gid: u32) -> bool {
        let (low, high) = self.get();
        low <= gid && gid <= high
    }
}

impl Default for GroupRange { fn default() -> Self { Self::new() } }

/// Result of validating a write to the two-value leaf. `Reset` is the Linux
/// outcome for an inverted window: the pair is replaced by the disabled window
/// rather than rejected. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RangeWrite { Accept(u32, u32), Invalid }

/// Validate one already-parsed pair. An out-of-range or reserved-invalid group
/// id is rejected; an inverted window disables ping sockets. # C: O(1)
pub fn validate(low: u64, high: u64) -> RangeWrite {
    if low > GID_MAX || high > GID_MAX { return RangeWrite::Invalid; }
    if low as u32 == INVALID_GID || high as u32 == INVALID_GID { return RangeWrite::Invalid; }
    if high < low { return RangeWrite::Accept(DISABLED_LOW, DISABLED_HIGH); }
    RangeWrite::Accept(low as u32, high as u32)
}

/// Parse the whitespace-separated value vector this leaf carries. A write that
/// names only the first value keeps the live second value; trailing tokens
/// beyond the pair are consumed and ignored, and an all-whitespace write leaves
/// the pair untouched. # C: O(len)
pub fn parse_write(src: &[u8], live: (u32, u32)) -> Result<Option<(u64, u64)>, ()> {
    let text = core::str::from_utf8(src).map_err(|_| ())?;
    let mut fields = text.split_whitespace();
    let Some(first) = fields.next() else { return Ok(None) };
    let low = parse_field(first)?;
    let high = match fields.next() {
        Some(value) => parse_field(value)?,
        None => live.1 as u64,
    };
    Ok(Some((low, high)))
}

/// One `unsigned long` field: decimal, optionally signed with a leading `-`
/// that the unsigned vector handler rejects. # C: O(len)
fn parse_field(field: &str) -> Result<u64, ()> {
    if field.is_empty() || !field.bytes().all(|b| b.is_ascii_digit()) { return Err(()); }
    field.parse::<u64>().map_err(|_| ())
}

/// Render the live pair the way the two-value vector handler prints it. # C: O(1)
pub fn format(pair: (u32, u32)) -> alloc::vec::Vec<u8> {
    alloc::format!("{}\t{}\n", pair.0, pair.1).into_bytes()
}

/// The caller's group identity as the admission ladder consumes it.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CallerGroups<'a> {
    pub egid: u32,
    pub supplementary: &'a [u32],
}

/// Whether this caller may open an ICMP datagram endpoint: the effective group
/// inside the window, or any supplementary group inside it. # C: O(ngroups)
pub fn admits(range: (u32, u32), caller: CallerGroups<'_>) -> bool {
    let (low, high) = range;
    if low <= caller.egid && caller.egid <= high { return true; }
    caller.supplementary.iter().any(|gid| low <= *gid && *gid <= high)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_window_is_disabled_and_admits_nobody() {
        let range = GroupRange::new();
        assert_eq!(range.get(), (DISABLED_LOW, DISABLED_HIGH));
        assert_eq!(format(range.get()), b"1\t0\n".to_vec());
        for gid in [0u32, 1, 2, 1000, u32::MAX - 1] {
            assert!(!range.contains(gid), "gid {gid} must not be admitted by the disabled window");
            assert!(!admits(range.get(), CallerGroups { egid: gid, supplementary: &[] }));
        }
    }

    #[test]
    fn distribution_default_opens_the_window_to_every_group() {
        let range = GroupRange::new();
        let parsed = parse_write(b"0 2147483647", range.get()).unwrap().unwrap();
        let RangeWrite::Accept(low, high) = validate(parsed.0, parsed.1) else { panic!("rejected") };
        range.set(low, high);
        assert_eq!(range.get(), (0, 2_147_483_647));
        assert_eq!(format(range.get()), b"0\t2147483647\n".to_vec());
        assert!(admits(range.get(), CallerGroups { egid: 1000, supplementary: &[] }));
        assert!(admits(range.get(), CallerGroups { egid: 0, supplementary: &[] }));
        assert!(!admits(range.get(), CallerGroups { egid: 2_147_483_648, supplementary: &[] }));
    }

    #[test]
    fn supplementary_group_alone_admits_the_caller() {
        let range = (100u32, 200u32);
        assert!(!admits(range, CallerGroups { egid: 1000, supplementary: &[7, 42] }));
        assert!(admits(range, CallerGroups { egid: 1000, supplementary: &[7, 150] }));
        assert!(admits(range, CallerGroups { egid: 100, supplementary: &[] }));
        assert!(admits(range, CallerGroups { egid: 200, supplementary: &[] }));
        assert!(!admits(range, CallerGroups { egid: 201, supplementary: &[99] }));
    }

    #[test]
    fn inverted_window_resets_to_the_disabled_pair() {
        assert_eq!(validate(10, 5), RangeWrite::Accept(DISABLED_LOW, DISABLED_HIGH));
        assert_eq!(validate(1, 0), RangeWrite::Accept(DISABLED_LOW, DISABLED_HIGH));
        assert_eq!(validate(5, 5), RangeWrite::Accept(5, 5));
    }

    #[test]
    fn reserved_invalid_group_and_out_of_range_values_are_rejected() {
        assert_eq!(validate(0, GID_MAX), RangeWrite::Invalid);
        assert_eq!(validate(GID_MAX, GID_MAX), RangeWrite::Invalid);
        assert_eq!(validate(0, GID_MAX + 1), RangeWrite::Invalid);
        assert_eq!(validate(0, GID_MAX - 1), RangeWrite::Accept(0, u32::MAX - 1));
    }

    #[test]
    fn single_field_write_keeps_the_live_high_bound() {
        assert_eq!(parse_write(b"5\n", (0, 400)), Ok(Some((5, 400))));
        assert_eq!(parse_write(b"  12\t99  \n", (0, 400)), Ok(Some((12, 99))));
        // A vector handler consumes the pair and ignores what follows it.
        assert_eq!(parse_write(b"1 2 3", (0, 400)), Ok(Some((1, 2))));
        assert_eq!(parse_write(b"   \n", (0, 400)), Ok(None));
    }

    #[test]
    fn malformed_fields_are_rejected_before_the_live_pair_moves() {
        assert_eq!(parse_write(b"abc", (0, 400)), Err(()));
        assert_eq!(parse_write(b"-1 5", (0, 400)), Err(()));
        assert_eq!(parse_write(b"0 -2", (0, 400)), Err(()));
        assert_eq!(parse_write(b"0x10 5", (0, 400)), Err(()));
        assert_eq!(parse_write(b"99999999999999999999 0", (0, 400)), Err(()));
    }
}
