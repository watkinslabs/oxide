// The rows `/proc/net/netlink` reports.
//
// A netlink socket's receive backlog is the one observable that separates
// "the kernel never delivered the message" from "it delivered it and the
// process never read it". With the file a header-only stub, neither could be
// told apart from outside the kernel, and three investigations into a service
// that appeared to ignore its notifications had nothing to measure.

extern crate alloc;

use alloc::vec::Vec;

/// One live netlink socket, in the fields the reference reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcRow {
    /// Stable per-socket identity, standing in for the reference's `%pK`.
    pub sk: u64,
    pub protocol: u16,
    pub port_id: u32,
    /// Low 32 multicast groups, as `sockaddr_nl.nl_groups` carries them.
    pub groups: u32,
    /// Bytes queued and unread — the reference's `sk_rmem_alloc`.
    pub rmem: usize,
    pub wmem: usize,
    /// Whether a dump is in progress (`cb_running`).
    pub dump: u32,
    pub locks: u32,
    pub drops: usize,
    pub ino: u64,
}

/// Render the table the reference prints. # C: O(N rows)
pub fn render(rows: &[ProcRow]) -> Vec<u8> {
    use core::fmt::Write as _;
    let mut s = alloc::string::String::from(
        "sk               Eth Pid        Groups   Rmem     Wmem     Dump  Locks    Drops    Inode\n");
    for r in rows {
        let _ = writeln!(s, "{:016x} {:<3} {:<10} {:08x} {:<8} {:<8} {:<5} {:<8} {:<8} {:<8}",
            r.sk, r.protocol, r.port_id, r.groups, r.rmem, r.wmem, r.dump, r.locks, r.drops, r.ino);
    }
    s.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROW: ProcRow = ProcRow { sk: 0xffff_8000_1234_5678, protocol: 0, port_id: 291,
        groups: 0x0111, rmem: 4096, wmem: 0, dump: 0, locks: 2, drops: 0, ino: 40123 };

    #[test]
    fn an_empty_table_is_still_the_header_the_reference_prints() {
        let out = render(&[]);
        let text = core::str::from_utf8(&out).unwrap();
        assert_eq!(text.lines().count(), 1);
        assert!(text.starts_with("sk               Eth Pid        Groups   Rmem     Wmem     Dump  Locks    Drops    Inode"));
        assert!(text.ends_with('\n'));
    }

    #[test]
    fn a_row_reports_each_field_in_the_columns_the_reference_uses() {
        let out = render(&[ROW]);
        let text = core::str::from_utf8(&out).unwrap();
        let line = text.lines().nth(1).expect("one row");
        let f: alloc::vec::Vec<&str> = line.split_whitespace().collect();
        assert_eq!(f.len(), 10, "ten columns, matching the header");
        assert_eq!(f[1], "0", "Eth is the protocol");
        assert_eq!(f[2], "291", "Pid is the port id");
        assert_eq!(f[3], "00000111", "Groups is the low group word in hex, zero-padded to 8");
        assert_eq!(f[4], "4096", "Rmem is the unread backlog");
        assert_eq!(f[9], "40123", "Inode last");
    }

    #[test]
    fn the_backlog_column_is_what_distinguishes_undelivered_from_unread() {
        // The whole point of the file: a socket with bytes queued has been
        // delivered to and not read, which no other observable shows.
        let mut queued = ROW; queued.rmem = 8192;
        let mut drained = ROW; drained.rmem = 0;
        let a = render(&[queued]);
        let b = render(&[drained]);
        assert_ne!(a, b);
        assert!(core::str::from_utf8(&a).unwrap().contains("8192"));
    }

    #[test]
    fn every_row_gets_its_own_line() {
        let mut second = ROW; second.port_id = 7; second.ino = 9;
        let out = render(&[ROW, second]);
        assert_eq!(core::str::from_utf8(&out).unwrap().lines().count(), 3);
    }
}
