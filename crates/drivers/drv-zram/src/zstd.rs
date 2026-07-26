//! Linux zram Zstandard backend, on the in-tree `zstd` crate.
//!
//! Frames are standard RFC 8878, so a page written by this backend is readable
//! by any zstd implementation and vice versa -- which matters because writeback
//! puts them on a real block device.
//!
//! The per-CPU stream mirrors Linux's `zcomp`: one context per possible CPU,
//! built on first use. Unlike the vendored codec this replaced, `Encoder` and
//! `Decoder` are a handful of pointers rather than ~15 KiB and ~13.6 KiB by
//! value, so the boxing here buys allocation REUSE across pages rather than
//! stack safety.

use alloc::boxed::Box;
use alloc::vec::Vec;

use block::{BlockError, KResult};
use sync::{Spinlock, TaskList, MAX_CPUS};
use zstd::{Decoder, Dictionary, Encoder, Level};

/// Generic zcomp value meaning this backend selects its upstream default.
const PARAM_NOT_SET: i32 = crate::deflate::PARAM_NOT_SET;

/// Level range Linux accepts for this backend (`ZSTD_minCLevel()` ..
/// `ZSTD_maxCLevel()`), kept verbatim so `algorithm_params level=N` behaves as
/// it does on Linux.
const MIN_LEVEL: i32 = -131_072;
const MAX_LEVEL: i32 = 22;
const DEFAULT_LEVEL: i32 = 3;

/// Level boundaries the codec's three effort tiers map onto. Levels below the
/// default trade ratio for speed; levels well above it are asking for the
/// deepest match search available.
const FAST_LEVEL_MAX: i32 = 2;
const DEFAULT_LEVEL_MAX: i32 = 9;

fn configured_level(level: i32) -> KResult<Level> {
    let level = if level == PARAM_NOT_SET { DEFAULT_LEVEL } else { level };
    if !(MIN_LEVEL..=MAX_LEVEL).contains(&level) { return Err(BlockError::Einval); }
    Ok(if level <= FAST_LEVEL_MAX { Level::Fast }
        else if level <= DEFAULT_LEVEL_MAX { Level::Default }
        else { Level::Best })
}

/// Validate the selected zstd level before zram allocates its device state.
/// # C: O(1)
pub(super) fn validate_initialization(level: i32) -> KResult<()> {
    configured_level(level)?;
    Ok(())
}

/// Immutable level and dictionary shared by every per-CPU stream.
struct Parameters {
    /// Parsed once per device. `None` is the common no-dictionary case, which
    /// then costs nothing per page.
    dictionary: Option<Box<Dictionary>>,
    level: Level,
}

impl Parameters {
    fn new(level: i32, dictionary: &[u8]) -> KResult<Self> {
        let level = configured_level(level)?;
        let dictionary = if dictionary.is_empty() { None } else {
            Some(Box::new(Dictionary::parse(dictionary).map_err(|_| BlockError::Einval)?))
        };
        Ok(Self { dictionary, level })
    }
}

/// Per-CPU contexts, built LAZILY and PER DIRECTION: a device that is only ever
/// read never builds an encoder, and vice versa.
struct Stream { encoder: Option<Encoder>, decoder: Option<Decoder> }

// SAFETY: `Streams` holds the owning per-CPU spinlock across every access, so a
// `Stream` is only ever touched by one CPU at a time, and neither `Encoder` nor
// `Decoder` retains a borrow of its input past the call that supplied it.
unsafe impl Send for Stream {}

/// Linux zcomp-equivalent Zstd contexts, one stream per possible CPU.
pub(crate) struct Streams {
    parameters: Parameters,
    streams: Vec<Spinlock<Option<Box<Stream>>, TaskList>>,
}

fn current_cpu() -> usize {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    { use hal::CpuOps; (hal_x86_64::X86CpuOps::current_cpu() as usize).min(MAX_CPUS - 1) }
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    { use hal::CpuOps; (hal_aarch64::ArmCpuOps::current_cpu() as usize).min(MAX_CPUS - 1) }
    #[cfg(not(target_os = "oxide-kernel"))]
    { 0 }
}

impl Streams {
    /// # C: O(dictionary bytes)
    pub(crate) fn new(level: i32, dictionary: &[u8]) -> KResult<Self> {
        let mut streams = Vec::with_capacity(MAX_CPUS);
        for _ in 0..MAX_CPUS { streams.push(Spinlock::new(None)); }
        Ok(Self { parameters: Parameters::new(level, dictionary)?, streams })
    }

    /// Compress one page using this CPU's encoder, built on first use.
    /// # C: O(page bytes × selected compression level)
    pub(crate) fn compress(&self, bytes: &[u8]) -> KResult<Vec<u8>> {
        let mut guard = self.streams[current_cpu()].lock();
        let stream = guard.get_or_insert_with(|| Box::new(Stream { encoder: None, decoder: None }));
        if stream.encoder.is_none() {
            let mut encoder = Encoder::new(self.parameters.level);
            if let Some(d) = &self.parameters.dictionary { encoder.set_dictionary(d); }
            stream.encoder = Some(encoder);
        }
        let encoder = stream.encoder.as_mut().ok_or(BlockError::Enomem)?;
        let mut out = Vec::new();
        encoder.compress_frame(bytes, &mut out).map_err(|_| BlockError::Eio)?;
        Ok(out)
    }

    /// Decode exactly one page using this CPU's decoder, built on first use.
    /// # C: O(frame bytes + page bytes)
    pub(crate) fn decompress(&self, bytes: &[u8], page: &mut [u8]) -> KResult<()> {
        let mut guard = self.streams[current_cpu()].lock();
        let stream = guard.get_or_insert_with(|| Box::new(Stream { encoder: None, decoder: None }));
        if stream.decoder.is_none() { stream.decoder = Some(Decoder::new()); }
        let decoder = stream.decoder.as_mut().ok_or(BlockError::Enomem)?;
        let written = decoder.decompress_page(bytes, page, self.parameters.dictionary.as_deref())
            .map_err(|_| BlockError::Eio)?;
        // A short page would leave stale bytes behind, which on the swap path is
        // silent corruption rather than a read error.
        if written != page.len() { return Err(BlockError::Eio); }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_level_linux_accepts_maps_onto_a_tier() {
        // The sysfs knob takes Linux's full range, so each end and the default
        // must resolve rather than be rejected.
        assert_eq!(configured_level(PARAM_NOT_SET).unwrap(), Level::Default);
        assert_eq!(configured_level(MIN_LEVEL).unwrap(), Level::Fast);
        assert_eq!(configured_level(1).unwrap(), Level::Fast);
        assert_eq!(configured_level(3).unwrap(), Level::Default);
        assert_eq!(configured_level(MAX_LEVEL).unwrap(), Level::Best);
        assert!(configured_level(MAX_LEVEL + 1).is_err());
        assert!(configured_level(MIN_LEVEL - 1).is_err());
    }

    #[test]
    fn a_page_round_trips_through_the_per_cpu_streams() {
        let streams = Streams::new(PARAM_NOT_SET, &[]).unwrap();
        let page: Vec<u8> = (0..4096u32).map(|i| (i % 37) as u8).collect();
        let frame = streams.compress(&page).unwrap();
        let mut back = alloc::vec![0u8; 4096];
        streams.decompress(&frame, &mut back).unwrap();
        assert_eq!(back, page);
    }

    #[test]
    fn a_dictionary_page_round_trips_and_needs_the_same_dictionary() {
        let mut dict = Vec::new();
        while dict.len() < 2048 { dict.extend_from_slice(b"zram page contents that repeat; "); }
        let streams = Streams::new(PARAM_NOT_SET, &dict).unwrap();
        let mut page = Vec::new();
        while page.len() < 4096 { page.extend_from_slice(b"zram page contents that repeat; "); }
        page.truncate(4096);
        let frame = streams.compress(&page).unwrap();
        let mut back = alloc::vec![0u8; 4096];
        streams.decompress(&frame, &mut back).unwrap();
        assert_eq!(back, page);

        // The same frame against a device with no dictionary must fail rather
        // than hand back a page of wrong bytes.
        let plain = Streams::new(PARAM_NOT_SET, &[]).unwrap();
        let mut back = alloc::vec![0u8; 4096];
        assert!(plain.decompress(&frame, &mut back).is_err());
    }

    #[test]
    fn a_uniform_page_compresses_to_almost_nothing() {
        // The most common compressible page on the swap path.
        let streams = Streams::new(PARAM_NOT_SET, &[]).unwrap();
        let frame = streams.compress(&alloc::vec![0u8; 4096]).unwrap();
        assert!(frame.len() <= 16, "a zero page cost {} bytes", frame.len());
    }

    #[test]
    fn a_corrupt_frame_is_reported_rather_than_decoded() {
        let streams = Streams::new(PARAM_NOT_SET, &[]).unwrap();
        let page: Vec<u8> = (0..4096u32).map(|i| (i % 37) as u8).collect();
        let mut frame = streams.compress(&page).unwrap();
        frame[0] ^= 0xFF;
        let mut back = alloc::vec![0u8; 4096];
        assert!(streams.decompress(&frame, &mut back).is_err());
    }
}
