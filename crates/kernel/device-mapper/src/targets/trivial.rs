//! `zero`, `error` and `delay`: the three targets with no interesting
//! addressing. They matter anyway — `error` is what a table holds where a
//! volume is missing, and `zero` is what a sparse volume reads as.

extern crate alloc;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use block::BlockOp;
use syscall::errno::Errno;

use crate::args::parse_u64;
use crate::target::{Ctr, DevMode, DmDev, DmIo, DmResult, DmTarget, MapResult, StatusType,
                    TargetFeatures, TargetType};

const PLAIN: TargetFeatures =
    TargetFeatures { singleton: false, always_writeable: false, immutable: false, wildcard: false, nowait: false };

/// `zero`: reads produce zeros, writes are discarded.
pub mod zero {
    use super::*;

    /// The registered `zero` mapping type.
    pub const TYPE: TargetType = TargetType { name: "zero", version: [1, 1, 0], features: PLAIN, ctr };

    struct Zero;

    fn ctr(c: &mut Ctr<'_>) -> DmResult<Arc<dyn DmTarget>> {
        if !c.argv.is_empty() { return Err(c.fail("No arguments required", Errno::Einval)); }
        Ok(Arc::new(Zero))
    }

    impl DmTarget for Zero {
        fn map(&self, io: &mut DmIo<'_>) -> DmResult<MapResult> {
            match io.op {
                BlockOp::Read => {
                    io.data.clear();
                    io.data.resize((io.n_sectors as usize) * (crate::uapi::SECTOR_BYTES as usize), 0);
                    Ok(MapResult::Submitted)
                }
                // A write to a device with no storage is accepted and dropped,
                // which is what makes `zero` usable as the tail of a sparse
                // table rather than a wall.
                BlockOp::Write | BlockOp::Discard | BlockOp::WriteZeroes { .. } | BlockOp::Flush =>
                    Ok(MapResult::Submitted),
            }
        }
        fn status(&self, _kind: StatusType) -> String { String::new() }
        fn iterate_devices(&self) -> Vec<DmDev> { Vec::new() }
    }
}

/// `error`: every I/O fails. What a table holds where a device is missing.
pub mod error {
    use super::*;

    /// The registered `error` mapping type.
    pub const TYPE: TargetType = TargetType { name: "error", version: [1, 7, 0], features: PLAIN, ctr };

    struct ErrorTarget { dev: Option<DmDev>, start: u64 }

    /// Two argument forms: none, or a device and an offset that the target
    /// records but never reads. The recorded pair exists so a table can be
    /// reloaded from its own report after a volume has been replaced by an
    /// error mapping.
    fn ctr(c: &mut Ctr<'_>) -> DmResult<Arc<dyn DmTarget>> {
        if c.argv.len() != 2 { return Ok(Arc::new(ErrorTarget { dev: None, start: 0 })); }
        let start = parse_u64(c.argv[1]).ok_or_else(|| c.fail("Invalid device sector", Errno::Einval))?;
        let dev = c.resolver.get_device(c.argv[0], DevMode::RW)
            .map_err(|e| { c.error = Some("Device lookup failed"); e })?;
        Ok(Arc::new(ErrorTarget { dev: Some(dev), start }))
    }

    impl DmTarget for ErrorTarget {
        fn map(&self, _io: &mut DmIo<'_>) -> DmResult<MapResult> { Ok(MapResult::Kill) }
        fn status(&self, kind: StatusType) -> String {
            match (kind, &self.dev) {
                (StatusType::Table, Some(d)) => format!("{} {}", d.name, self.start),
                _ => String::new(),
            }
        }
        fn iterate_devices(&self) -> Vec<DmDev> { self.dev.clone().into_iter().collect() }
    }
}

/// `delay`: a linear mapping that holds each I/O back, per operation class.
pub mod delay {
    use super::*;
    use core::sync::atomic::{AtomicU64, Ordering};

    /// The registered `delay` mapping type.
    pub const TYPE: TargetType = TargetType { name: "delay", version: [1, 4, 0], features: PLAIN, ctr };

    /// One operation class's destination and hold time.
    pub struct Class {
        /// Destination device.
        pub dev: DmDev,
        /// First sector on it.
        pub start: u64,
        /// Milliseconds an I/O of this class is held.
        pub delay_ms: u32,
        /// I/Os of this class placed so far, which the status report prints.
        pub ops: AtomicU64,
    }

    /// Reads, writes and flushes, each with their own destination and delay.
    pub struct Delay {
        begin: u64,
        read: Class,
        write: Class,
        flush: Class,
        /// How many triples the table line carried, so the report echoes the
        /// shape it was given rather than a normalised one.
        argc: usize,
    }

    fn triple(c: &mut Ctr<'_>, i: usize) -> DmResult<Class> {
        let start = parse_u64(c.argv[i + 1])
            .ok_or_else(|| c.fail("Invalid device sector", Errno::Einval))?;
        let delay_ms = crate::args::parse_u32(c.argv[i + 2])
            .ok_or_else(|| c.fail("Invalid delay", Errno::Einval))?;
        let dev = c.resolver.get_device(c.argv[i], DevMode::RW)
            .map_err(|e| { c.error = Some("Device lookup failed"); e })?;
        Ok(Class { dev, start, delay_ms, ops: AtomicU64::new(0) })
    }

    fn ctr(c: &mut Ctr<'_>) -> DmResult<Arc<dyn DmTarget>> {
        let argc = c.argv.len();
        if !matches!(argc, 3 | 6 | 9) {
            return Err(c.fail("Requires exactly 3, 6 or 9 arguments", Errno::Einval));
        }
        let read = triple(c, 0)?;
        // Six arguments give reads and writes their own destinations, and the
        // flush class reuses the write one; three give all three the same.
        let write = if argc >= 6 { triple(c, 3)? } else { triple(c, 0)? };
        let flush = if argc == 9 { triple(c, 6)? } else if argc == 6 { triple(c, 3)? } else { triple(c, 0)? };
        Ok(Arc::new(Delay { begin: c.begin, read, write, flush, argc }))
    }

    impl Delay {
        fn class(&self, op: BlockOp) -> &Class {
            match op {
                BlockOp::Read => &self.read,
                BlockOp::Flush => &self.flush,
                _ => &self.write,
            }
        }
    }

    impl DmTarget for Delay {
        fn map(&self, io: &mut DmIo<'_>) -> DmResult<MapResult> {
            let c = self.class(io.op);
            c.ops.fetch_add(1, Ordering::Relaxed);
            Ok(MapResult::Remapped { dev: c.dev.bdev.clone(), sector: c.start + (io.sector - self.begin) })
        }

        fn status(&self, kind: StatusType) -> String {
            match kind {
                StatusType::Info => format!("{} {} {}",
                    self.read.ops.load(Ordering::Relaxed),
                    self.write.ops.load(Ordering::Relaxed),
                    self.flush.ops.load(Ordering::Relaxed)),
                StatusType::Table => {
                    let one = |c: &Class| format!("{} {} {}", c.dev.name, c.start, c.delay_ms);
                    match self.argc {
                        3 => one(&self.read),
                        6 => format!("{} {}", one(&self.read), one(&self.write)),
                        _ => format!("{} {} {}", one(&self.read), one(&self.write), one(&self.flush)),
                    }
                }
            }
        }

        fn iterate_devices(&self) -> Vec<DmDev> {
            alloc::vec![self.read.dev.clone(), self.write.dev.clone(), self.flush.dev.clone()]
        }
    }
}
