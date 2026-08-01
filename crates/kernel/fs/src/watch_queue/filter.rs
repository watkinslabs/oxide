// The notification filter: which records a queue accepts.
//
// A queue with NO filter accepts everything. A queue with a filter accepts
// only what a rule matches — the default flips to reject the moment a filter
// exists, so installing a filter can never widen what a caller sees.

use alloc::vec::Vec;

use syscall::errno::Errno;

use super::uapi::*;

/// One type rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypeFilter {
    pub ty: u32,
    pub info_filter: u32,
    pub info_mask: u32,
    /// Bitmap of accepted subtypes; bit `n` accepts subtype `n`.
    pub subtype_filter: u32,
}

/// An installed filter.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Filter {
    pub filters: Vec<TypeFilter>,
}

impl Filter {
    /// Does this filter accept the record? # C: O(filters)
    pub fn accepts(&self, ty: u32, subtype: u32, info: u32) -> bool {
        // The subtype bitmap covers 0..=31 here; a subtype above that has no
        // bit to be selected by and is therefore not accepted, which is the
        // reject-by-default rule applied to a subtype the rule cannot name.
        self.filters.iter().any(|f| {
            f.ty == ty
                && subtype < u32::BITS
                && f.subtype_filter & (1 << subtype) != 0
                && info & f.info_mask == f.info_filter
        })
    }

    /// Parse a copied `struct watch_notification_filter` and its rule array.
    ///
    /// The rules that reject:
    ///   * a count of zero, or above the ceiling, and a nonzero reserved word
    ///     are EINVAL — a reserved word set means the caller wants something
    ///     this kernel has no definition of;
    ///   * a rule whose `info_filter` has bits outside its own `info_mask` can
    ///     never match, and a mask covering the record LENGTH would filter on
    ///     a field the sender sets, not on anything about the event.
    ///
    /// A rule naming a type this kernel does not define is DROPPED rather than
    /// rejected, so a program built against a later kernel still installs its
    /// remaining rules. # C: O(nr)
    pub fn parse(header: &[u8], rules: &[u8], nr: u32) -> Result<Self, Errno> {
        let reserved = word(header, WATCH_FILTER_RESERVED_OFFSET);
        if nr == 0 || nr > WATCH_FILTER_MAX || reserved != 0 { return Err(Errno::Einval); }
        let mut out: Vec<TypeFilter> = Vec::new();
        for i in 0..nr as usize {
            let base = i * WATCH_TYPE_FILTER_SIZE;
            let f = &rules[base..base + WATCH_TYPE_FILTER_SIZE];
            let info_filter = word(f, WATCH_TYPE_FILTER_INFO_FILTER_OFFSET);
            let info_mask = word(f, WATCH_TYPE_FILTER_INFO_MASK_OFFSET);
            if info_filter & !info_mask != 0 || info_mask & WATCH_INFO_LENGTH != 0 {
                return Err(Errno::Einval);
            }
            let ty = word(f, WATCH_TYPE_FILTER_TYPE_OFFSET);
            if ty >= WATCH_TYPE_NR { continue; }
            out.push(TypeFilter {
                ty, info_filter, info_mask,
                subtype_filter: word(f, WATCH_TYPE_FILTER_SUBTYPE_OFFSET),
            });
        }
        Ok(Self { filters: out })
    }
}

fn word(b: &[u8], off: usize) -> u32 {
    u32::from_ne_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}
