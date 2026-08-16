//! `crypt`: an encrypted view of another device.
//!
//! Module manifest:
//! - `spec`: the cipher-string and key grammar, and the optional features.
//! - `iv`: producing a sector's initialisation vector.
//! - `mode`: the chaining modes, each its own encrypt/decrypt pair.
//!
//! What is decided here and nowhere else: which sector number the IV counts,
//! and where the encryption unit boundary falls. Both are places where a
//! plausible wrong answer produces a volume that reads back as noise.

extern crate alloc;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use block::{BlockOp, QueueLimits};
use syscall::errno::Errno;

use crate::args::parse_u64;
use crate::target::{Ctr, DevMode, DmDev, DmIo, DmResult, DmTarget, MapResult, StatusType,
                    TargetFeatures, TargetType};
use crate::uapi::SECTOR_BYTES;

pub mod spec;
pub mod iv;
pub mod mode;

pub use spec::{parse_cipher, parse_features, parse_key, ChainMode, CipherSpec, Features, IvMode, KeySource};

/// The registered `crypt` mapping type.
pub const TYPE: TargetType = TargetType {
    name: "crypt",
    version: [1, 28, 0],
    features: TargetFeatures { singleton: false, always_writeable: false, immutable: false, wildcard: false, nowait: false },
    ctr,
};

/// One encrypted mapping.
pub struct Crypt {
    /// First sector of the mapped device this target covers.
    pub begin: u64,
    /// First sector on the backing device.
    pub start: u64,
    /// Offset added to the sector number before it becomes an IV. It shifts
    /// the IV sequence WITHOUT shifting the data, which is how a volume keeps
    /// its ciphertext valid after its header grows.
    pub iv_offset: u64,
    /// The backing device.
    pub dev: DmDev,
    /// The parsed cipher specification.
    pub spec: CipherSpec,
    /// Optional table-line features.
    pub features: Features,
    /// How the key was given, for the table report.
    pub key_source: KeySource,
    keys: mode::ModeKeys,
    iv_key: iv::IvKey,
}

fn ctr(c: &mut Ctr<'_>) -> DmResult<Arc<dyn DmTarget>> {
    if c.argv.len() < 5 { return Err(c.fail("Not enough arguments", Errno::Einval)); }
    let features = parse_features(&c.argv[5..])
        .map_err(|e| { c.error = Some("Invalid feature arguments"); e })?;
    let spec = parse_cipher(c.argv[0])
        .map_err(|e| { c.error = Some("Unknown cipher specification"); e })?;
    if spec.cipher != "aes" { return Err(c.fail("Unsupported bulk cipher", Errno::Enotsup)); }
    let key_source = parse_key(c.argv[1])
        .map_err(|e| { c.error = Some("Error decoding and setting key"); e })?;
    let iv_offset = parse_u64(c.argv[2]).ok_or_else(|| c.fail("Invalid iv_offset sector", Errno::Einval))?;
    let start = parse_u64(c.argv[4]).ok_or_else(|| c.fail("Invalid device sector", Errno::Einval))?;
    let dev = c.resolver.get_device(c.argv[3], DevMode::RW)
        .map_err(|e| { c.error = Some("Device lookup failed"); e })?;

    // A key held in the keyring is not present at construction time. Refusing
    // is honest: a target that constructed with no key would encrypt with
    // whatever it had, and the volume would be unreadable afterwards.
    let KeySource::Hex(key) = &key_source else {
        return Err(c.fail("Keyring key references are not resolvable here", Errno::Enokey));
    };
    let keys = mode::keys_for(spec.chain, key)
        .ok_or_else(|| c.fail("Error decoding and setting key", Errno::Einval))?;
    let iv_key = iv::prepare(&spec.iv, mode::iv_key_material(spec.chain, key), features.sector_size)
        .ok_or_else(|| c.fail("Error creating IV", Errno::Einval))?;

    // The mapping must be a whole number of encryption units, or the last one
    // would be a partial block the mode cannot transform.
    let unit_sectors = (features.sector_size as u64) / SECTOR_BYTES;
    if unit_sectors == 0 || c.len % unit_sectors != 0 {
        return Err(c.fail("Device size is not a multiple of sector_size", Errno::Einval));
    }

    Ok(Arc::new(Crypt {
        begin: c.begin, start, iv_offset, dev, spec, features,
        key_source: key_source.clone(), keys, iv_key,
    }))
}

impl Crypt {
    /// Sector on the backing device that `sector` lands on. `iv_offset` is
    /// deliberately absent: it moves the IV, not the data. # C: O(1)
    pub fn map_sector(&self, sector: u64) -> u64 { self.start + (sector - self.begin) }

    /// Sector number the IV is computed from.
    ///
    /// Counted in 512-byte sectors by default, whatever the encryption unit
    /// is; only the large-sector feature makes it count units. Getting this
    /// backwards gives every unit after the first the wrong IV.
    /// # C: O(1)
    pub fn iv_sector(&self, sector: u64) -> u64 {
        let s = (sector - self.begin) + self.iv_offset;
        if self.features.iv_large_sectors {
            s >> (self.features.sector_size.trailing_zeros() - crate::uapi::SECTOR_SHIFT)
        } else {
            s
        }
    }

    /// Transform the payload of one I/O in place, one encryption unit at a
    /// time. # C: O(data.len())
    fn transform(&self, first_sector: u64, data: &mut [u8], encrypting: bool) {
        let unit = self.features.sector_size as usize;
        let per_unit_sectors = (unit as u64) / SECTOR_BYTES;
        for (i, chunk) in data.chunks_exact_mut(unit).enumerate() {
            let sector = first_sector + (i as u64) * per_unit_sectors;
            let v = iv::generate(&self.spec.iv, &self.iv_key, self.iv_sector(sector),
                                 self.features.sector_size);
            if encrypting { mode::encrypt(self.spec.chain, &self.keys, &v, chunk); }
            else { mode::decrypt(self.spec.chain, &self.keys, &v, chunk); }
        }
    }
}

impl DmTarget for Crypt {
    fn map(&self, io: &mut DmIo<'_>) -> DmResult<MapResult> {
        let phys = self.map_sector(io.sector);
        match io.op {
            BlockOp::Write => {
                self.transform(io.sector, io.data, true);
                Ok(MapResult::Remapped { dev: self.dev.bdev.clone(), sector: phys })
            }
            BlockOp::Read => {
                crate::device::io::forward(&*self.dev.bdev, BlockOp::Read, phys, io.n_sectors, io.data)
                    .map_err(|_| Errno::Eio)?;
                self.transform(io.sector, io.data, false);
                Ok(MapResult::Submitted)
            }
            // A discard tells an observer which regions of an encrypted volume
            // hold nothing, so it is dropped unless the table asked for it.
            BlockOp::Discard if !self.features.allow_discards => Ok(MapResult::Submitted),
            _ => Ok(MapResult::Remapped { dev: self.dev.bdev.clone(), sector: phys }),
        }
    }

    /// The encryption unit is the largest piece that can be transformed
    /// independently, so no I/O may straddle one.
    fn max_io_len(&self) -> u64 { (self.features.sector_size as u64) / SECTOR_BYTES }

    fn status(&self, kind: StatusType) -> String {
        match kind {
            StatusType::Info => String::new(),
            StatusType::Table => {
                let key = match &self.key_source {
                    KeySource::Hex(k) => spec::key_hex(k),
                    KeySource::Keyring { size, key_type, desc } => format!(":{size}:{key_type}:{desc}"),
                };
                let mut s = format!("{} {} {} {} {}",
                    self.spec.text, key, self.iv_offset, self.dev.name, self.start);
                let f = spec::features_text(&self.features);
                if !f.is_empty() { s.push(' '); s.push_str(&f); }
                s
            }
        }
    }

    fn iterate_devices(&self) -> Vec<DmDev> { alloc::vec![self.dev.clone()] }

    fn io_hints(&self, limits: &mut QueueLimits) {
        // The device addresses in encryption units: a partial unit cannot be
        // written without the rest of it.
        if let Ok(next) = QueueLimits::new(self.features.sector_size, self.features.sector_size,
                                           self.features.sector_size, 0) {
            *limits = next;
        }
    }
}
