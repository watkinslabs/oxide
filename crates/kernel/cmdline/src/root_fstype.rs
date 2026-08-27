// `rootfstype=`: which filesystem types the root mount may be tried as.
//
// Linux's `mount_block_root` walks a candidate list and mounts the root as the
// first type that accepts the device. `rootfstype=` narrows that list to the
// comma-separated names it carries, in the order it carries them; absent, the
// kernel tries every filesystem registered for a block device. This module
// owns the ORDER, not the mounting: it answers "which types, in which order",
// and the boot path attempts each until one opens.

use crate::token::value;

/// Candidate root filesystem types when `rootfstype=` is absent: every block
/// filesystem this kernel can mount as a root, most likely first. Mirrors the
/// registered-type walk rather than a single hardcoded answer.
pub const DEFAULT_CANDIDATES: &[&[u8]] = &[b"ext4", b"squashfs"];

/// Maximum candidate types honoured from one `rootfstype=` value. A longer
/// list is truncated rather than refused, matching a boot line that names more
/// types than the kernel has registered.
pub const MAX_CANDIDATES: usize = 8;

/// The root filesystem types to try, in order.
///
/// `Some(list)` whenever `rootfstype=` names at least one non-empty type;
/// `None` when the parameter is absent or carries only empty names, which
/// leaves [`DEFAULT_CANDIDATES`] in force.
/// # C: O(line length)
pub fn root_fstypes_in(line: &[u8]) -> Option<([&[u8]; MAX_CANDIDATES], usize)> {
    let v = value(line, b"rootfstype")?;
    let mut out: [&[u8]; MAX_CANDIDATES] = [b""; MAX_CANDIDATES];
    let mut n = 0;
    for name in v.split(|b| *b == b',') {
        if name.is_empty() { continue; }
        if n == MAX_CANDIDATES { break; }
        out[n] = name;
        n += 1;
    }
    if n == 0 { None } else { Some((out, n)) }
}

/// Does the boot line ask for a read-only root?
///
/// `ro` and `rw` are bare tokens and the LAST one wins, so a line that appends
/// `rw` to a template carrying `ro` mounts writable. Absent both, Linux mounts
/// the root read-only and leaves the remount to userspace.
/// # C: O(line length)
pub fn root_readonly_in(line: &[u8]) -> bool {
    let mut ro = true;
    for tok in line.split(|b| b.is_ascii_whitespace()) {
        match tok { b"ro" => ro = true, b"rw" => ro = false, _ => {} }
    }
    ro
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The candidate list a line produces, defaulted the way the boot path
    /// defaults it. Returned as a slice pair so the test module needs no
    /// allocator.
    fn types<'a>(line: &'a [u8], buf: &'a mut [&'a [u8]; MAX_CANDIDATES]) -> &'a [&'a [u8]] {
        match root_fstypes_in(line) {
            Some((list, n)) => { *buf = list; &buf[..n] }
            None => DEFAULT_CANDIDATES,
        }
    }

    #[test]
    fn absent_leaves_the_default_candidate_order() {
        let mut b = [&b""[..]; MAX_CANDIDATES];
        assert_eq!(types(b"root=/dev/vda rw", &mut b), &[&b"ext4"[..], &b"squashfs"[..]]);
    }

    #[test]
    fn a_single_type_is_the_only_candidate() {
        let mut b = [&b""[..]; MAX_CANDIDATES];
        assert_eq!(types(b"root=/dev/vda2 rootfstype=squashfs ro", &mut b), &[&b"squashfs"[..]]);
    }

    #[test]
    fn a_list_keeps_the_order_it_was_written_in() {
        let mut b = [&b""[..]; MAX_CANDIDATES];
        assert_eq!(types(b"rootfstype=squashfs,ext4 root=/dev/vda", &mut b),
            &[&b"squashfs"[..], &b"ext4"[..]]);
    }

    #[test]
    fn empty_names_in_the_list_are_skipped() {
        let mut b = [&b""[..]; MAX_CANDIDATES];
        assert_eq!(types(b"rootfstype=,squashfs,,ext4,", &mut b),
            &[&b"squashfs"[..], &b"ext4"[..]]);
    }

    #[test]
    fn a_value_of_only_separators_leaves_the_default() {
        assert!(root_fstypes_in(b"rootfstype=,,,").is_none());
    }

    #[test]
    fn an_empty_value_leaves_the_default() {
        assert!(root_fstypes_in(b"rootfstype= root=/dev/vda").is_none());
    }

    #[test]
    fn the_list_is_truncated_at_the_candidate_ceiling() {
        let (_, n) = root_fstypes_in(b"rootfstype=a,b,c,d,e,f,g,h,i,j").unwrap();
        assert_eq!(n, MAX_CANDIDATES);
    }

    #[test]
    fn a_longer_parameter_name_is_not_matched() {
        assert!(root_fstypes_in(b"rootfstypes=squashfs").is_none());
        assert!(root_fstypes_in(b"myrootfstype=squashfs").is_none());
    }

    #[test]
    fn root_is_read_only_unless_the_line_says_otherwise() {
        assert!(root_readonly_in(b"root=/dev/vda2 rootfstype=squashfs"));
        assert!(!root_readonly_in(b"root=/dev/vda rw"));
        assert!(root_readonly_in(b"root=/dev/vda ro"));
    }

    #[test]
    fn the_last_of_ro_and_rw_wins() {
        assert!(!root_readonly_in(b"ro root=/dev/vda rw"));
        assert!(root_readonly_in(b"rw root=/dev/vda ro"));
    }

    #[test]
    fn ro_inside_another_token_does_not_count() {
        assert!(!root_readonly_in(b"root=/dev/vda rw introspect=ro-ish"));
    }
}
