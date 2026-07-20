//! Linux zram Zstandard backend using standard RFC 8878 frames.

use alloc::vec::Vec;

use block::{BlockError, KResult};
use structured_zstd::decoding::{Dictionary, DictionaryHandle, FrameDecoder};
use structured_zstd::encoding::{CompressionLevel, FrameCompressor};
use sync::{Spinlock, TaskList, MAX_CPUS};

/// Generic zcomp value meaning this backend selects its upstream default.
const PARAM_NOT_SET: i32 = crate::deflate::PARAM_NOT_SET;

fn configured_level(level: i32) -> KResult<CompressionLevel> {
    let level = if level == PARAM_NOT_SET { CompressionLevel::DEFAULT_LEVEL } else { level };
    if !(CompressionLevel::MIN_LEVEL..=CompressionLevel::MAX_LEVEL).contains(&level) {
        return Err(BlockError::Einval);
    }
    Ok(CompressionLevel::from_level(level))
}

/// Validate the selected zstd level before zram allocates its device state.
/// # C: O(1)
pub(super) fn validate_initialization(level: i32) -> KResult<()> {
    configured_level(level)?;
    Ok(())
}

/// Immutable dictionary and level state shared by every per-CPU stream.
#[derive(Clone)]
struct Parameters {
    encoder_dictionary: Option<Dictionary>,
    decoder_dictionary: Option<DictionaryHandle>,
    dictionary_id_visible: bool,
    level: CompressionLevel,
}

impl Parameters {
    fn new(level: i32, dictionary: &[u8]) -> KResult<Self> {
        let level = configured_level(level)?;
        let dictionary_id_visible = dictionary.starts_with(&structured_zstd::decoding::MAGIC_NUM);
        let dictionary = if dictionary.is_empty() { None } else {
            Some(Dictionary::from_zstd_dictionary_bytes(dictionary).map_err(|_| BlockError::Einval)?)
        };
        let decoder_dictionary = dictionary.as_ref().map(|dictionary| DictionaryHandle::from_dictionary(dictionary.clone()));
        Ok(Self { encoder_dictionary: dictionary, decoder_dictionary, dictionary_id_visible, level })
    }
}

struct Stream { encoder: FrameCompressor, decoder: FrameDecoder }

// SAFETY: `Streams::with_stream` holds the owning per-CPU spinlock for every
// access. zram uses only `compress_independent_frame`, which clears the
// encoder's transient borrowed input pointer before returning.
unsafe impl Send for Stream {}

impl Stream {
    fn new(parameters: &Parameters) -> KResult<Self> {
        let mut encoder = FrameCompressor::new(parameters.level);
        if let Some(dictionary) = &parameters.encoder_dictionary {
            encoder.set_dictionary(dictionary.clone()).map_err(|_| BlockError::Einval)?;
            encoder.set_dictionary_id_flag(parameters.dictionary_id_visible);
        }
        Ok(Self { encoder, decoder: FrameDecoder::new() })
    }
}

/// Linux zcomp-equivalent Zstd contexts, one stream per possible CPU.
pub(crate) struct Streams { parameters: Parameters, streams: Vec<Spinlock<Option<Stream>, TaskList>> }

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

    fn with_stream<T>(&self, run: impl FnOnce(&mut Stream, &Parameters) -> KResult<T>) -> KResult<T> {
        let mut stream = self.streams[current_cpu()].lock();
        if stream.is_none() { *stream = Some(Stream::new(&self.parameters)?); }
        run(stream.as_mut().ok_or(BlockError::Enomem)?, &self.parameters)
    }

    /// Compress one page using its priority-owned initialized context.
    /// # C: O(page bytes × selected compression level)
    pub(crate) fn compress(&self, bytes: &[u8]) -> KResult<Vec<u8>> {
        self.with_stream(|stream, _| Ok(stream.encoder.compress_independent_frame(bytes)))
    }

    /// Decode exactly one page using its priority-owned initialized context.
    /// # C: O(frame bytes + page bytes)
    pub(crate) fn decompress(&self, bytes: &[u8], page: &mut [u8]) -> KResult<()> {
        self.with_stream(|stream, parameters| {
            let written = match &parameters.decoder_dictionary {
                Some(dictionary) => stream.decoder.decode_all_with_dict_handle(bytes, page, dictionary),
                None => stream.decoder.decode_all(bytes, page),
            }.map_err(|_| BlockError::Eio)?;
            if written != page.len() { return Err(BlockError::Eio); }
            Ok(())
        })
    }
}
