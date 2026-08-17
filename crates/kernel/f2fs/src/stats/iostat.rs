//! Bytes and requests, split by what asked for them.
//!
//! Two numbers per kind — total bytes and number of requests — and the mean
//! derived from the pair at report time. The split is by ORIGIN, not by
//! device operation: the point of the report is to say which layer generated
//! the traffic, so an application write and the checkpoint write that
//! eventually carries it are different kinds even when they move the same
//! bytes.
//!
//! Two kinds are rollups rather than sites: the application's read total and
//! its write total are raised by the direct and buffered kinds, so no site
//! reports them and they can never disagree with their parts. A compressed
//! file's traffic is counted twice on purpose — once under the plain kind and
//! once under the compressed one — because the compressed figure answers
//! "how much of the traffic was compressed", which a partition of the total
//! could not.

use alloc::string::String;
use alloc::vec::Vec;

use crate::fsattr::line_str;

/// Where a request came from.
///
/// The numbering is the report's own row order and nothing else depends on
/// it, but it is written down because the array is indexed by it.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(usize)]
pub enum Io {
    // Writes.
    AppDirect = 0,
    AppBuffered,
    /// Rollup of the two above.
    AppWrite,
    AppMapped,
    AppBufferedCdata,
    AppMappedCdata,
    FsData,
    FsCdata,
    FsNode,
    FsMeta,
    FsGcData,
    FsGcNode,
    FsCpData,
    FsCpNode,
    FsCpMeta,
    // Reads.
    AppDirectRead,
    AppBufferedRead,
    /// Rollup of the two above.
    AppRead,
    AppMappedRead,
    AppBufferedCdataRead,
    AppMappedCdataRead,
    FsDataRead,
    FsGdataRead,
    FsCdataRead,
    FsNodeRead,
    FsMetaRead,
    // Neither.
    FsDiscard,
    FsFlush,
    FsZoneReset,
}

/// How many kinds there are.
pub const NR_IO_TYPE: usize = Io::FsZoneReset as usize + 1;

/// Orders of read request the volume distinguishes when it reports how big
/// the reads it served were.
pub const NR_PAGE_ORDERS: usize = 13;

impl Io {
    /// # C: O(1)
    pub const fn idx(self) -> usize { self as usize }
}

/// Bytes and requests per kind.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Iostat {
    /// Whether sites report at all. Off by default: the accounting costs a
    /// pair of additions on every block, and a report nobody asked for is
    /// not worth paying for on every write.
    pub enabled: bool,
    pub bytes: [u64; NR_IO_TYPE],
    pub count: [u64; NR_IO_TYPE],
    /// Reads served, by the order of the request.
    pub read_folio_count: [u64; NR_PAGE_ORDERS],
}

impl Default for Iostat {
    fn default() -> Self { Self::new() }
}

impl Iostat {
    /// # C: O(1)
    pub const fn new() -> Self {
        Iostat { enabled: false, bytes: [0; NR_IO_TYPE], count: [0; NR_IO_TYPE],
                 read_folio_count: [0; NR_PAGE_ORDERS] }
    }

    /// Turn reporting on or off, discarding nothing.
    ///
    /// The totals survive the switch: a reader that turns accounting off and
    /// on again is narrowing what it pays for, not asking for the history to
    /// be thrown away.
    /// # C: O(1)
    pub fn enable(&mut self, on: bool) { self.enabled = on; }

    /// Forget everything counted so far. # C: O(1)
    pub fn reset(&mut self) {
        let on = self.enabled;
        *self = Iostat::new();
        self.enabled = on;
    }

    /// Record one request of `kind` moving `bytes`.
    ///
    /// `compressed` says whether the file the request is for is a compressed
    /// one, which adds the compressed twin of the kind where one exists.
    /// # C: O(1)
    pub fn update(&mut self, kind: Io, bytes: u64, compressed: bool) {
        if !self.enabled { return; }
        self.raw(kind, bytes);
        match kind {
            Io::AppBuffered | Io::AppDirect => self.raw(Io::AppWrite, bytes),
            Io::AppBufferedRead | Io::AppDirectRead => self.raw(Io::AppRead, bytes),
            _ => {}
        }
        if !compressed { return; }
        let twin = match kind {
            Io::AppBuffered => Some(Io::AppBufferedCdata),
            Io::AppBufferedRead => Some(Io::AppBufferedCdataRead),
            Io::AppMapped => Some(Io::AppMappedCdata),
            Io::AppMappedRead => Some(Io::AppMappedCdataRead),
            Io::FsData => Some(Io::FsCdata),
            Io::FsDataRead => Some(Io::FsCdataRead),
            _ => None,
        };
        if let Some(t) = twin { self.raw(t, bytes); }
    }

    /// # C: O(1)
    fn raw(&mut self, kind: Io, bytes: u64) {
        let i = kind.idx();
        self.bytes[i] += bytes;
        self.count[i] += 1;
    }

    /// Record a read of `order` — the request's size as a power of two
    /// blocks. An order past what is distinguished lands in the last bucket
    /// rather than being dropped.
    /// # C: O(1)
    pub fn read_folio(&mut self, order: usize) {
        if !self.enabled { return; }
        self.read_folio_count[order.min(NR_PAGE_ORDERS - 1)] += 1;
    }

    /// Mean bytes per request of one kind, or zero when there were none.
    /// # C: O(1)
    pub fn avg(&self, kind: Io) -> u64 {
        let i = kind.idx();
        if self.count[i] == 0 { 0 } else { self.bytes[i] / self.count[i] }
    }
}

/// One row: the label, the two totals, and the mean. # C: O(1)
fn row(out: &mut String, name: &str, s: &Iostat, kind: Io) {
    let i = kind.idx();
    let label = alloc::format!("{name}:");
    out.push_str(&alloc::format!("{:<23} {:<16} {:<16} {:<16}\n",
                                 label, s.bytes[i], s.count[i], s.avg(kind)));
}

/// The whole report.
///
/// Empty when accounting is off, which is the state that says "nothing was
/// measured" — a table of zeroes would say measurement ran and found nothing.
/// `now` is the wall clock in seconds; nothing below this layer can read one.
/// # C: O(N kinds)
pub fn info_body(s: &Iostat, now: u64) -> Vec<u8> {
    if !s.enabled { return Vec::new(); }
    let mut o = String::new();
    o.push_str(&alloc::format!("time:\t\t{now:<16}\n"));
    o.push_str(&alloc::format!("\t\t\t{:<16} {:<16} {:<16}\n", "io_bytes", "count", "avg_bytes"));

    o.push_str("[WRITE]\n");
    row(&mut o, "app buffered data", s, Io::AppBuffered);
    row(&mut o, "app direct data", s, Io::AppDirect);
    row(&mut o, "app mapped data", s, Io::AppMapped);
    row(&mut o, "app buffered cdata", s, Io::AppBufferedCdata);
    row(&mut o, "app mapped cdata", s, Io::AppMappedCdata);
    row(&mut o, "fs data", s, Io::FsData);
    row(&mut o, "fs cdata", s, Io::FsCdata);
    row(&mut o, "fs node", s, Io::FsNode);
    row(&mut o, "fs meta", s, Io::FsMeta);
    row(&mut o, "fs gc data", s, Io::FsGcData);
    row(&mut o, "fs gc node", s, Io::FsGcNode);
    row(&mut o, "fs cp data", s, Io::FsCpData);
    row(&mut o, "fs cp node", s, Io::FsCpNode);
    row(&mut o, "fs cp meta", s, Io::FsCpMeta);

    o.push_str("[READ]\n");
    row(&mut o, "app buffered data", s, Io::AppBufferedRead);
    row(&mut o, "app direct data", s, Io::AppDirectRead);
    row(&mut o, "app mapped data", s, Io::AppMappedRead);
    row(&mut o, "app buffered cdata", s, Io::AppBufferedCdataRead);
    row(&mut o, "app mapped cdata", s, Io::AppMappedCdataRead);
    row(&mut o, "fs data", s, Io::FsDataRead);
    row(&mut o, "fs gc data", s, Io::FsGdataRead);
    row(&mut o, "fs cdata", s, Io::FsCdataRead);
    row(&mut o, "fs node", s, Io::FsNodeRead);
    row(&mut o, "fs meta", s, Io::FsMetaRead);

    o.push_str(&alloc::format!("{:<23}", "fs read folio order:"));
    for n in s.read_folio_count.iter() { o.push_str(&alloc::format!(" {n}")); }
    o.push('\n');

    o.push_str("[OTHER]\n");
    row(&mut o, "fs discard", s, Io::FsDiscard);
    row(&mut o, "fs flush", s, Io::FsFlush);
    row(&mut o, "fs zone reset", s, Io::FsZoneReset);
    o.into_bytes()
}

/// The report's own name under a mount's directory. # C: O(1)
pub const INFO_NAME: &str = "iostat_info";

/// One line of text, for a caller assembling a report by hand. # C: O(len)
pub fn line(s: &str) -> Vec<u8> { line_str(s) }
