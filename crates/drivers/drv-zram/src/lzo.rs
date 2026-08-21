//! Linux zcomp-compatible LZO1X codec with reusable per-CPU work memory.

use alloc::vec;
use alloc::vec::Vec;

use block::{BlockError, KResult};
use sync::{Spinlock, TaskList, MAX_CPUS};

/// One LZO1X match dictionary belongs to one CPU's zcomp stream. It is
/// allocated on the first LZO request and reused for the device lifetime.
#[derive(Default)]
struct Stream { dictionary: Option<lzo1x::encode::Workspace> }

/// Return the bounded logical CPU that owns one zcomp stream. # C: O(1)
fn current_cpu() -> usize {
        #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
        { use hal::CpuOps; (hal_x86_64::X86CpuOps::current_cpu() as usize).min(MAX_CPUS - 1) }
        #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
        { use hal::CpuOps; (hal_aarch64::ArmCpuOps::current_cpu() as usize).min(MAX_CPUS - 1) }
        #[cfg(not(target_os = "oxide-kernel"))]
        { 0 }
}

/// Reusable LZO contexts. Each CPU has one locked zcomp stream, allowing
/// reset to destroy every context only after its active operation has ended.
///
/// Heap `Vec` (like the zstd backend) — NOT an inline `[_; MAX_CPUS]` array:
/// with `MAX_CPUS=256`, an inline array is a multi-KB value that
/// `Compressor::new` would build + move on the KERNEL STACK, overflowing the
/// 16 KiB `THREAD_SIZE` stack during zram disksize init (C213).
pub(crate) struct Streams { streams: Vec<Spinlock<Stream, TaskList>> }

impl Streams {
    /// # C: O(number of possible CPUs)
    pub(crate) fn new() -> Self {
        let mut streams = Vec::with_capacity(MAX_CPUS);
        for _ in 0..MAX_CPUS { streams.push(Spinlock::new(Stream::default())); }
        Self { streams }
    }

    /// Compress one zram page as an LZO1X stream. # C: O(page bytes)
    pub(crate) fn compress(&self, input: &[u8]) -> KResult<Vec<u8>> {
        self.compress_mode(input, false)
    }

    /// Compress one zram page as a version-one LZO-RLE stream. # C: O(page bytes)
    pub(crate) fn compress_rle(&self, input: &[u8]) -> KResult<Vec<u8>> {
        self.compress_mode(input, true)
    }

    fn compress_mode(&self, input: &[u8], rle: bool) -> KResult<Vec<u8>> {
        let mut stream = self.streams[current_cpu()].lock();
        if stream.dictionary.is_none() { stream.dictionary = Some(lzo1x::encode::Workspace::new()); }
        let dictionary = stream.dictionary.as_mut().ok_or(BlockError::Enomem)?;
        let mut output = vec![0; lzo1x::encode::worst_size(input.len())];
        let size = lzo1x::encode::compress_with(input, &mut output, rle, dictionary)
            .ok_or(BlockError::Eio)?;
        output.truncate(size);
        Ok(output)
    }
}

/// Decode one LZO1X stream into an exact zram page. # C: O(page bytes)
pub(crate) fn decompress(input: &[u8], output: &mut [u8]) -> KResult<()> {
    let size = lzo1x::decode::decompress(input, output).map_err(|_| BlockError::Eio)?;
    if size == output.len() { Ok(()) } else { Err(BlockError::Eio) }
}
