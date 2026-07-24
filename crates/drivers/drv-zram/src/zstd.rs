//! Linux zram Zstandard backend using standard RFC 8878 frames.

use alloc::boxed::Box;
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
///
/// `encoder_dictionary` is BOXED: `Dictionary` inlines the FSE/Huffman decode
/// tables (~16 KiB), so an inline `Option<Dictionary>` would size this struct —
/// and hence `StreamOwner`/`Compressor` — to ~16 KiB and overflow the 16 KiB
/// kernel stack when `Compressor::new` builds it by value at disksize (C213).
/// Boxed, `Parameters` is pointer-sized and the default no-dictionary zram
/// never materializes a `Dictionary` at all.
#[derive(Clone)]
struct Parameters {
    encoder_dictionary: Option<Box<Dictionary>>,
    decoder_dictionary: Option<DictionaryHandle>,
    dictionary_id_visible: bool,
    level: CompressionLevel,
}

impl Parameters {
    fn new(level: i32, dictionary: &[u8]) -> KResult<Self> {
        let level = configured_level(level)?;
        let dictionary_id_visible = dictionary.starts_with(&structured_zstd::decoding::MAGIC_NUM);
        let (encoder_dictionary, decoder_dictionary) = if dictionary.is_empty() { (None, None) } else {
            let (enc, dec) = parse_dictionary(dictionary)?;
            (Some(enc), Some(dec))
        };
        Ok(Self { encoder_dictionary, decoder_dictionary, dictionary_id_visible, level })
    }
}

/// Parse a zstd dictionary onto the HEAP. `#[inline(never)]` is load-bearing:
/// `Dictionary::from_zstd_dictionary_bytes` returns a ~16 KiB value BY VALUE,
/// and `Box::new(that)` builds it on the stack before moving it to the heap. If
/// this were inlined into the compressor-init chain, the compiler would reserve
/// those 16 KiB in `CompressionConfig::initialize`'s frame — even on the common
/// no-dictionary path — overflowing the 16 KiB kernel stack (C213). Out-of-line,
/// the temporary lives only in THIS frame, entered only when a dict is present.
#[inline(never)]
fn parse_dictionary(raw: &[u8]) -> KResult<(Box<Dictionary>, DictionaryHandle)> {
    let dict = Dictionary::from_zstd_dictionary_bytes(raw).map_err(|_| BlockError::Einval)?;
    // Clone here too (16 KiB by-value) so BOTH big dictionary temporaries stay
    // in this out-of-line frame, never in the compressor-init chain.
    let handle = DictionaryHandle::from_dictionary(dict.clone());
    Ok((Box::new(dict), handle))
}

/// Per-CPU zstd contexts, built LAZILY and PER DIRECTION. `FrameCompressor`
/// (~15.4 KiB) and `FrameDecoder` (~13.6 KiB) are each nearly a full 16 KiB
/// kernel stack by value, so (a) they must live on the heap and (b) only the
/// direction actually exercised is ever materialized — a decode never builds
/// the 15 KiB encoder, and vice-versa (C213).
struct Stream { encoder: Option<Box<FrameCompressor>>, decoder: Option<Box<FrameDecoder>> }

// SAFETY: `Streams` holds the owning per-CPU spinlock for every access. zram
// uses only `compress_independent_frame`, which clears the encoder's transient
// borrowed input pointer before returning.
unsafe impl Send for Stream {}

/// Build this CPU's encoder on the heap. `#[inline(never)]` is load-bearing:
/// `FrameCompressor` is ~15.4 KiB by value, so `Box::new(FrameCompressor::new)`
/// needs a ~15.4 KiB stack temporary. Out-of-line it stays in THIS shallow
/// frame instead of stacking on top of the block-I/O → compress call chain and
/// overflowing the 16 KiB kernel stack.
#[inline(never)]
fn new_encoder(parameters: &Parameters) -> KResult<Box<FrameCompressor>> {
    let mut encoder = FrameCompressor::new(parameters.level);
    if let Some(dictionary) = &parameters.encoder_dictionary {
        encoder.set_dictionary((**dictionary).clone()).map_err(|_| BlockError::Einval)?;
        encoder.set_dictionary_id_flag(parameters.dictionary_id_visible);
    }
    Ok(Box::new(encoder))
}

/// Build this CPU's decoder on the heap. `#[inline(never)]` for the same reason
/// — `FrameDecoder` is ~13.6 KiB by value.
#[inline(never)]
fn new_decoder() -> Box<FrameDecoder> { Box::new(FrameDecoder::new()) }

/// Linux zcomp-equivalent Zstd contexts, one stream per possible CPU.
///
/// The per-CPU stream is `Option<Box<Stream>>`, NOT `Option<Stream>`: `Stream`
/// inlines a `FrameCompressor` (~29 KiB), so an unboxed `Spinlock<Option<Stream>>`
/// Vec element is a ~29 KiB type. `Streams::new` builds each `Spinlock::new(None)`
/// element BY VALUE on the stack before moving it into the heap Vec — a 29 KiB
/// stack temporary that the compiler reserves in `CompressionConfig::initialize`'s
/// frame for the zstd branch, overflowing the 16 KiB kernel stack even when a
/// different algorithm is selected (C213). Boxed, the element is pointer-sized.
pub(crate) struct Streams { parameters: Parameters, streams: Vec<Spinlock<Option<Box<Stream>>, TaskList>> }

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
        if stream.encoder.is_none() { stream.encoder = Some(new_encoder(&self.parameters)?); }
        Ok(stream.encoder.as_mut().ok_or(BlockError::Enomem)?.compress_independent_frame(bytes))
    }

    /// Decode exactly one page using this CPU's decoder, built on first use.
    /// # C: O(frame bytes + page bytes)
    pub(crate) fn decompress(&self, bytes: &[u8], page: &mut [u8]) -> KResult<()> {
        let mut guard = self.streams[current_cpu()].lock();
        let stream = guard.get_or_insert_with(|| Box::new(Stream { encoder: None, decoder: None }));
        if stream.decoder.is_none() { stream.decoder = Some(new_decoder()); }
        let decoder = stream.decoder.as_mut().ok_or(BlockError::Enomem)?;
        let written = match &self.parameters.decoder_dictionary {
            Some(dictionary) => decoder.decode_all_with_dict_handle(bytes, page, dictionary),
            None => decoder.decode_all(bytes, page),
        }.map_err(|_| BlockError::Eio)?;
        if written != page.len() { return Err(BlockError::Eio); }
        Ok(())
    }
}
