// The x86_64 `bzImage` loader: `kexec_bzImage64_ops`.
//
// Registered in `file_load::LOADERS` on x86_64 only. It recognises a 64-bit,
// relocatable, above-4-GiB-capable bzImage, places four segments, and hands
// control to a purgatory rather than to the kernel — see `purgatory`.
//
// Module manifest:
// - `uapi`:       boot-protocol field offsets, flag bits and placement floors.
// - `header`:     the probe ladder and the setup-header fields the layout needs.
// - `bootparams`: the boot-parameter page, built as bytes at ABI offsets.
// - `layout`:     the segment placement, the digest and the purgatory patches.
//
// Compiled on every architecture even though only x86_64 registers it: the
// decision logic is ungated so the hosted suite exercises it, and a loader that
// only existed on its own target could be checked by nothing but a boot.

pub mod uapi;
pub mod header;
pub mod bootparams;
pub mod layout;

use crate::file_load::{purgatory, FileLoader, LoadCtx, Loaded};
use crate::validate::KResult;

/// x86_64 `bzImage` loader.
pub struct BzImage64;

impl FileLoader for BzImage64 {
    /// # C: O(1)
    fn probe(&self, kernel: &[u8]) -> KResult<()> { header::probe(kernel) }

    /// # C: O(kernel + initrd)
    fn load(&self, ctx: &LoadCtx) -> KResult<Loaded> {
        layout::plan(&ctx.img.kernel, &ctx.img.initrd, ctx.img.cmdline_str(),
                     ctx.place, ctx.system, purgatory::image()?)
    }
}
