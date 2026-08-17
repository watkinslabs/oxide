//! Saying what a mount put back.
//!
//! A replay is the one thing a mount does that changes the filesystem without
//! anybody asking. Doing it silently means an operator cannot tell a volume
//! that came up clean from one that had a crash's tail rewritten into it, and
//! cannot tell either from a volume whose chain was found and DROPPED — which
//! is a loss of writes an `fsync` promised, and the case most worth saying out
//! loud.
//!
//! The decision of what to say is separated from the saying so it can be
//! tested: the emit is a sink nothing in a hosted build reads, and a test that
//! called it would assert nothing.

use super::replay::Recovery;

/// What the counts mean, in the order they are announced.
pub const FIELDS: [&[u8]; 4] = [b" nodes=", b" inodes=", b" dentries=", b" blocks="];

/// What a mount has to announce about the chain it found.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Announce {
    /// Nothing followed the checkpoint, so there is nothing to say. Every
    /// ordinary mount is this one, and a line per mount saying so would bury
    /// the two that matter.
    Silent,
    /// A chain was found and this mount could not replay it.
    Skipped,
    /// A chain was replayed. Counts in [`FIELDS`] order.
    Replayed([u32; 4]),
}

/// What the replay's outcome is worth saying. # C: O(1)
pub fn announce_for(r: Recovery) -> Announce {
    match r {
        Recovery::Clean => Announce::Silent,
        Recovery::Skipped => Announce::Skipped,
        Recovery::Replayed(d) => Announce::Replayed([d.nodes, d.inodes, d.dentries, d.blocks]),
    }
}

/// Put the announcement in the log. # C: O(1)
pub fn emit(a: Announce) {
    const LVL: u32 = klog::syslog::LOGLEVEL_NOTICE;
    match a {
        Announce::Silent => {}
        Announce::Skipped => klog::write_raw_at(
            b"f2fs: a log written since the last checkpoint was NOT replayed\n", LVL),
        Announce::Replayed(counts) => {
            klog::write_raw_at(b"f2fs: replayed the log written since the last checkpoint:", LVL);
            for (field, n) in FIELDS.iter().zip(counts) {
                klog::write_raw_at(field, LVL);
                klog::write_dec_at(u64::from(n), LVL);
            }
            klog::write_raw_at(b"\n", LVL);
        }
    }
}

#[cfg(test)]
#[path = "../../tests/recover/report.rs"]
mod tests;
