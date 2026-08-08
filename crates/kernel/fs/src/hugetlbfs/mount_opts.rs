// hugetlbfs option parsing and validation.
//
// Pure: no allocator contact, no globals, no privilege lookups — the whole
// grammar and every refusal is decided here from the option string and the
// pool size, so a hosted test drives all of it.

use pmm::hugetlb::HugePageSize;
use vfs::{KResult, VfsError};

use super::limits::{MODE_MASK, NO_LIMIT};

/// A `size=`/`min_size=` value: bytes, or a percentage of the pool.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(super) enum SizeOpt {
    Bytes(u64),
    Percent(u64),
}

impl SizeOpt {
    /// Huge pages this option names, given the pool's target size.
    ///
    /// A percentage is of the POOL, not of RAM: a mount can only ever be
    /// backed by pages the pool holds, so sizing it against total memory would
    /// promise capacity that cannot exist.
    /// # C: O(1)
    pub(super) fn to_hpages(self, size: HugePageSize, pool_max: u64) -> i64 {
        let shift = size.shift();
        let bytes = match self {
            SizeOpt::Bytes(b)   => b,
            SizeOpt::Percent(p) => ((p << shift).saturating_mul(pool_max)) / 100,
        };
        (bytes >> shift) as i64
    }
}

/// Parsed hugetlbfs mount options. `None` means "not named", which is a
/// distinct answer from a named zero.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct HugetlbfsOpts {
    pub uid:       Option<u32>,
    pub gid:       Option<u32>,
    pub mode:      Option<u16>,
    pub size:      Option<SizeOpt>,
    pub min_size:  Option<SizeOpt>,
    pub nr_inodes: Option<u64>,
    pub pagesize:  Option<HugePageSize>,
}

/// The two page counts a mount enforces, after resolving its size options
/// against the pool.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(super) struct ResolvedSizes {
    pub max_hpages: i64,
    pub min_hpages: i64,
}

impl HugetlbfsOpts {
    /// The granule this mount serves.
    /// # C: O(1)
    pub(super) fn size(&self) -> HugePageSize {
        self.pagesize.unwrap_or_else(HugePageSize::default_size)
    }

    /// Resolve `size=`/`min_size=` to page counts and refuse a pair that
    /// cannot both hold.
    ///
    /// A minimum above the maximum is refused rather than clamped: the mount
    /// would reserve more than it can ever hand out, and every allocation past
    /// the maximum would fail against a reservation that already succeeded.
    /// # C: O(1)
    pub(super) fn resolve(&self, pool_max: u64) -> KResult<ResolvedSizes> {
        let size = self.size();
        let max_hpages = self.size.map_or(NO_LIMIT, |s| s.to_hpages(size, pool_max));
        let min_hpages = self.min_size.map_or(NO_LIMIT, |s| s.to_hpages(size, pool_max));
        if self.size.is_some() && min_hpages > max_hpages { return Err(VfsError::Einval); }
        Ok(ResolvedSizes { max_hpages, min_hpages })
    }

    /// Files this mount admits, or [`NO_LIMIT`].
    /// # C: O(1)
    pub(super) fn max_inodes(&self) -> i64 {
        self.nr_inodes.map_or(NO_LIMIT, |n| n as i64)
    }
}

/// `memparse`: a decimal count with an optional binary-scale suffix, and an
/// optional trailing `%` turning it into a percentage.
///
/// The leading character must be a digit: a bare `k`/`m`/`g` parses as the
/// scale of an absent number, which is not a size anyone meant to write.
/// # C: O(len)
fn memparse(s: &str) -> Option<SizeOpt> {
    let b = s.as_bytes();
    if b.is_empty() || !b[0].is_ascii_digit() { return None; }
    let mut n: u64 = 0;
    let mut i = 0;
    while i < b.len() && b[i].is_ascii_digit() {
        n = n.checked_mul(10)?.checked_add((b[i] - b'0') as u64)?;
        i += 1;
    }
    let rest = &b[i..];
    let (shift, rest) = match rest.first() {
        Some(b'k') | Some(b'K') => (10u32, &rest[1..]),
        Some(b'm') | Some(b'M') => (20,    &rest[1..]),
        Some(b'g') | Some(b'G') => (30,    &rest[1..]),
        Some(b't') | Some(b'T') => (40,    &rest[1..]),
        _                       => (0,     rest),
    };
    let n = n.checked_shl(shift)?;
    match rest {
        []      => Some(SizeOpt::Bytes(n)),
        [b'%']  => Some(SizeOpt::Percent(n)),
        _       => None,
    }
}

/// A plain decimal count, with the same binary-scale suffixes.
/// # C: O(len)
fn memparse_count(s: &str) -> Option<u64> {
    match memparse(s)? { SizeOpt::Bytes(n) => Some(n), SizeOpt::Percent(_) => None }
}

/// An octal permission word.
/// # C: O(len)
fn parse_mode(s: &str) -> Option<u16> {
    let mut n: u32 = 0;
    if s.is_empty() { return None; }
    for c in s.bytes() {
        if !(b'0'..=b'7').contains(&c) { return None; }
        n = n.checked_mul(8)?.checked_add((c - b'0') as u32)?;
        if n > u16::MAX as u32 { return None; }
    }
    Some((n & MODE_MASK) as u16)
}

/// A decimal id.
/// # C: O(len)
fn parse_u32(s: &str) -> Option<u32> {
    if s.is_empty() { return None; }
    let mut n: u32 = 0;
    for c in s.bytes() {
        if !c.is_ascii_digit() { return None; }
        n = n.checked_mul(10)?.checked_add((c - b'0') as u32)?;
    }
    Some(n)
}

/// A `pagesize=` value: a byte size that must name a granule the pool serves.
/// # C: O(len)
fn parse_pagesize(s: &str) -> Option<HugePageSize> {
    let bytes = memparse_count(s)?;
    for g in [HugePageSize::Huge2M, HugePageSize::Huge1G] {
        if g.bytes() == bytes { return Some(g); }
    }
    None
}

/// Split an option string on commas, dropping empty fields.
/// # C: O(len)
fn split_opts(data: &str) -> impl Iterator<Item = &str> {
    data.split(',').map(str::trim).filter(|s| !s.is_empty())
}

/// Apply one `key=value` option, or refuse it.
///
/// A key this filesystem does not have, or a value it cannot read, fails the
/// mount. Accepting either would mount a filesystem that behaves differently
/// from what the caller asked for, with nothing to say so.
/// # C: O(len)
fn parse_one(opts: &mut HugetlbfsOpts, tok: &str) -> KResult<()> {
    let (key, val) = tok.split_once('=').ok_or(VfsError::Einval)?;
    match key {
        "uid"       => opts.uid       = Some(parse_u32(val).ok_or(VfsError::Einval)?),
        "gid"       => opts.gid       = Some(parse_u32(val).ok_or(VfsError::Einval)?),
        "mode"      => opts.mode      = Some(parse_mode(val).ok_or(VfsError::Einval)?),
        "size"      => opts.size      = Some(memparse(val).ok_or(VfsError::Einval)?),
        "min_size"  => opts.min_size  = Some(memparse(val).ok_or(VfsError::Einval)?),
        "nr_inodes" => opts.nr_inodes = Some(memparse_count(val).ok_or(VfsError::Einval)?),
        "pagesize"  => opts.pagesize  = Some(parse_pagesize(val).ok_or(VfsError::Einval)?),
        _           => return Err(VfsError::Einval),
    }
    Ok(())
}

/// Parse a whole `-o` option string.
/// # C: O(len)
pub(super) fn parse_opts(data: &str) -> KResult<HugetlbfsOpts> {
    let mut opts = HugetlbfsOpts::default();
    for tok in split_opts(data) { parse_one(&mut opts, tok)?; }
    Ok(opts)
}

#[cfg(test)]
mod tests {
    use super::*;

    const M2: u64 = 2 * 1024 * 1024;

    #[test]
    fn an_empty_option_string_names_nothing() {
        assert_eq!(parse_opts("").unwrap(), HugetlbfsOpts::default());
    }

    #[test]
    fn the_default_granule_is_used_when_pagesize_is_absent() {
        assert_eq!(parse_opts("").unwrap().size(), HugePageSize::default_size());
    }

    #[test]
    fn every_option_is_read_out_of_a_full_option_string() {
        let o = parse_opts("uid=1000,gid=1001,mode=1777,size=4G,min_size=2M,nr_inodes=64,pagesize=2M").unwrap();
        assert_eq!(o.uid, Some(1000));
        assert_eq!(o.gid, Some(1001));
        assert_eq!(o.mode, Some(0o1777));
        assert_eq!(o.size, Some(SizeOpt::Bytes(4 << 30)));
        assert_eq!(o.min_size, Some(SizeOpt::Bytes(M2)));
        assert_eq!(o.nr_inodes, Some(64));
        assert_eq!(o.pagesize, Some(HugePageSize::Huge2M));
    }

    #[test]
    fn a_size_suffix_scales_in_binary_units() {
        assert_eq!(memparse("1k"), Some(SizeOpt::Bytes(1024)));
        assert_eq!(memparse("1M"), Some(SizeOpt::Bytes(1 << 20)));
        assert_eq!(memparse("3g"), Some(SizeOpt::Bytes(3 << 30)));
        assert_eq!(memparse("2T"), Some(SizeOpt::Bytes(2 << 40)));
        assert_eq!(memparse("512"), Some(SizeOpt::Bytes(512)));
    }

    #[test]
    fn a_trailing_percent_makes_the_size_relative_to_the_pool() {
        assert_eq!(memparse("50%"), Some(SizeOpt::Percent(50)));
        // 50% of a 10-page pool is 5 pages.
        assert_eq!(SizeOpt::Percent(50).to_hpages(HugePageSize::Huge2M, 10), 5);
        assert_eq!(SizeOpt::Percent(100).to_hpages(HugePageSize::Huge2M, 7), 7);
    }

    #[test]
    fn a_size_without_a_leading_digit_is_refused() {
        // `memparse` accepts a bare suffix; the mount grammar must not.
        assert!(parse_opts("size=M").is_err());
        assert!(parse_opts("min_size=g").is_err());
        assert!(parse_opts("nr_inodes=k").is_err());
    }

    #[test]
    fn a_size_rounds_down_to_whole_huge_pages() {
        // 3 MiB is one whole 2 MiB page; the remainder is not a page.
        assert_eq!(SizeOpt::Bytes(3 * M2 / 2).to_hpages(HugePageSize::Huge2M, 0), 1);
        assert_eq!(SizeOpt::Bytes(M2 - 1).to_hpages(HugePageSize::Huge2M, 0), 0);
    }

    #[test]
    fn a_size_is_measured_in_the_mounts_own_granule() {
        let o = parse_opts("size=2G,pagesize=1G").unwrap();
        assert_eq!(o.resolve(0).unwrap().max_hpages, 2);
        let o2 = parse_opts("size=2G,pagesize=2M").unwrap();
        assert_eq!(o2.resolve(0).unwrap().max_hpages, 1024);
    }

    #[test]
    fn an_unnamed_size_leaves_the_mount_unlimited() {
        let r = parse_opts("mode=0755").unwrap().resolve(0).unwrap();
        assert_eq!((r.max_hpages, r.min_hpages), (NO_LIMIT, NO_LIMIT));
    }

    #[test]
    fn a_minimum_above_the_maximum_is_refused() {
        assert_eq!(parse_opts("size=2M,min_size=4M").unwrap().resolve(0), Err(VfsError::Einval));
    }

    #[test]
    fn a_minimum_equal_to_the_maximum_is_accepted() {
        assert!(parse_opts("size=4M,min_size=4M").unwrap().resolve(0).is_ok());
    }

    #[test]
    fn a_minimum_without_a_maximum_is_not_compared_against_one() {
        let r = parse_opts("min_size=4M").unwrap().resolve(0).unwrap();
        assert_eq!((r.max_hpages, r.min_hpages), (NO_LIMIT, 2));
    }

    #[test]
    fn a_pagesize_the_pool_does_not_serve_is_refused() {
        for v in ["4k", "64k", "512M", "0"] {
            assert!(parse_opts(&alloc::format!("pagesize={v}")).is_err(), "pagesize={v}");
        }
    }

    #[test]
    fn each_served_granule_is_accepted_as_a_pagesize() {
        assert_eq!(parse_opts("pagesize=2M").unwrap().pagesize, Some(HugePageSize::Huge2M));
        assert_eq!(parse_opts("pagesize=1G").unwrap().pagesize, Some(HugePageSize::Huge1G));
        assert_eq!(parse_opts("pagesize=2048k").unwrap().pagesize, Some(HugePageSize::Huge2M));
    }

    #[test]
    fn mode_is_octal_and_masked_to_the_permission_bits() {
        assert_eq!(parse_opts("mode=755").unwrap().mode, Some(0o755));
        assert_eq!(parse_opts("mode=1777").unwrap().mode, Some(0o1777));
        // Type bits a caller sets are not permission bits.
        assert_eq!(parse_opts("mode=40755").unwrap().mode, Some(0o755));
        assert!(parse_opts("mode=799").is_err());
    }

    #[test]
    fn a_key_hugetlbfs_does_not_have_fails_the_mount() {
        for o in ["noswap", "huge=always", "nr_blocks=4", "size"] {
            assert!(parse_opts(o).is_err(), "{o} must fail the mount");
        }
    }

    #[test]
    fn nr_inodes_becomes_the_mounts_file_ceiling() {
        assert_eq!(parse_opts("nr_inodes=64").unwrap().max_inodes(), 64);
        assert_eq!(parse_opts("nr_inodes=1k").unwrap().max_inodes(), 1024);
        assert_eq!(parse_opts("").unwrap().max_inodes(), NO_LIMIT);
    }

    #[test]
    fn a_percentage_is_not_a_valid_inode_count() {
        assert!(parse_opts("nr_inodes=50%").is_err());
    }
}
