//! Linux zcomp-compatible LZO1X codec with reusable per-CPU work memory.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use block::{BlockError, KResult};
use sync::{Spinlock, TaskList, MAX_CPUS};

/// One LZO1X match dictionary belongs to one CPU's zcomp stream. It is
/// allocated on the first LZO request and reused for the device lifetime.
#[derive(Default)]
struct Stream { dictionary: Option<Box<lzokay::compress::Dict>> }

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
pub(crate) struct Streams { streams: [Spinlock<Stream, TaskList>; MAX_CPUS] }

impl Streams {
    /// # C: O(number of possible CPUs)
    pub(crate) fn new() -> Self { Self { streams: core::array::from_fn(|_| Spinlock::new(Stream::default())) } }

    /// Compress one zram page as an LZO1X stream. # C: O(page bytes)
    pub(crate) fn compress(&self, input: &[u8]) -> KResult<Vec<u8>> {
        let mut stream = self.streams[current_cpu()].lock();
        if stream.dictionary.is_none() { stream.dictionary = Some(lzokay::compress::Dict::new()); }
        let dictionary = stream.dictionary.as_deref_mut().ok_or(BlockError::Enomem)?;
        let mut output = vec![0; lzokay::compress::compress_worst_size(input.len())];
        let size = lzokay::compress::compress_no_alloc(input, &mut output, dictionary).map_err(|_| BlockError::Eio)?;
        output.truncate(size);
        Ok(output)
    }

    /// Release all zcomp stream work memory after the zram reset transition.
    /// # C: O(number of possible CPUs)
    pub(crate) fn reset(&self) {
        for stream in &self.streams { stream.lock().dictionary = None; }
    }
}

/// Decode one LZO1X stream into an exact zram page. # C: O(page bytes)
pub(crate) fn decompress(input: &[u8], output: &mut [u8]) -> KResult<()> {
    let size = lzokay::decompress::decompress(input, output).map_err(|_| BlockError::Eio)?;
    if size == output.len() { Ok(()) } else { Err(BlockError::Eio) }
}
