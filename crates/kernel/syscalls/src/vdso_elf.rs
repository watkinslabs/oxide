// The vDSO image's dynamic-symbol resolver.
//
// UNGATED. `vdso.rs` is `#![cfg(target_os = "oxide-kernel")]` and its one case
// carried a second gate on top -- `#[cfg(target_arch = "aarch64")]` -- so it
// could only ever have compiled in an aarch64 KERNEL build, where `cargo test`
// does not run. It had never executed. The resolver is a pure walk over a byte
// image, so it belongs where it can be driven: it takes the image as an
// argument, and the gated caller passes the blob its own build carries.
//
// What the cases below are worth: this walk indexes into an untrusted-shaped
// buffer at offsets read out of that same buffer, and every one of those reads
// must refuse rather than panic. Nothing checked that.
//
// Dead on an x86_64 kernel build: that image exposes no kernel-owned restorer,
// so nothing there calls the walk. It is still compiled and still tested on
// every host, which is the point -- the aarch64 contract is no longer checked
// only by a build that runs no tests.
#![allow(dead_code)]

const SHT_DYNSYM: u32 = 11;
const SHT_STRTAB: u32 = 3;
const ELF64_SYM_SIZE: usize = 24;
const ELF_SHOFF: usize = 40;
const ELF_SHENTSIZE: usize = 58;
const ELF_SHNUM: usize = 60;

/// The kernel-owned signal restorer an AArch64 image exports.
pub(crate) const VDSO_SIGRETURN_SYMBOL: &[u8] = b"__kernel_rt_sigreturn";

/// Resolve a defined dynamic-symbol address from a vDSO image. The value is
/// an image virtual address, to be added to the mapped base. Every offset the
/// walk follows is read out of the image, so each read is bounded against the
/// image's own length and a corrupt one answers nothing rather than faulting.
/// # C: O(N_dynsym)
pub(crate) fn dynsym_vaddr(b: &[u8], name: &[u8]) -> Option<u64> {
    if b.len() < ELF_SHNUM + 2 { return None; }
    let shoff = u64::from_le_bytes(b[ELF_SHOFF..ELF_SHOFF + 8].try_into().ok()?) as usize;
    let shentsz = u16::from_le_bytes(b[ELF_SHENTSIZE..ELF_SHENTSIZE + 2].try_into().ok()?) as usize;
    let shnum = u16::from_le_bytes(b[ELF_SHNUM..ELF_SHNUM + 2].try_into().ok()?) as usize;
    if shentsz < 64 || shoff.checked_add(shentsz.checked_mul(shnum)?)? > b.len() { return None; }
    let mut dynsym = None;
    let mut dynstr_index = None;
    for i in 0..shnum {
        let off = shoff + i * shentsz;
        let ty = u32::from_le_bytes(b[off + 4..off + 8].try_into().ok()?);
        let data = u64::from_le_bytes(b[off + 24..off + 32].try_into().ok()?) as usize;
        let len = u64::from_le_bytes(b[off + 32..off + 40].try_into().ok()?) as usize;
        if data.checked_add(len)? > b.len() { return None; }
        if ty == SHT_DYNSYM {
            let link = u32::from_le_bytes(b[off + 40..off + 44].try_into().ok()?) as usize;
            dynsym = Some((data, len));
            dynstr_index = Some(link);
        }
    }
    let (symoff, symlen) = dynsym?;
    let stridx = dynstr_index?;
    if stridx >= shnum { return None; }
    let stroff = shoff + stridx * shentsz;
    let strty = u32::from_le_bytes(b[stroff + 4..stroff + 8].try_into().ok()?);
    if strty != SHT_STRTAB { return None; }
    let strdata = u64::from_le_bytes(b[stroff + 24..stroff + 32].try_into().ok()?) as usize;
    let strlen = u64::from_le_bytes(b[stroff + 32..stroff + 40].try_into().ok()?) as usize;
    if strdata.checked_add(strlen)? > b.len() { return None; }
    if symlen % ELF64_SYM_SIZE != 0 { return None; }
    let strtab = &b[strdata..strdata + strlen];
    for off in (symoff..symoff + symlen).step_by(ELF64_SYM_SIZE) {
        let noff = u32::from_le_bytes(b[off..off + 4].try_into().ok()?) as usize;
        let shndx = u16::from_le_bytes(b[off + 6..off + 8].try_into().ok()?);
        if shndx == 0 || noff >= strtab.len() { continue; }
        let tail = &strtab[noff..];
        let end = tail.iter().position(|c| *c == 0)?;
        if &tail[..end] == name {
            return Some(u64::from_le_bytes(b[off + 8..off + 16].try_into().ok()?));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both images this tree ships, so the aarch64 contract is checked on any
    /// host rather than only in an aarch64 kernel build, where no test runs.
    const AARCH64_IMAGE: &[u8] = include_bytes!("../vdso/vdso-aarch64.so");
    const X86_64_IMAGE: &[u8] = include_bytes!("../vdso/vdso-x86_64.so");

    /// The image must export the restorer signal delivery jumps to. Without
    /// it, an AArch64 handler returns through an address that resolves to
    /// nothing and the process dies on return from every signal.
    #[test]
    fn the_aarch64_image_exports_the_signal_restorer() {
        let at = dynsym_vaddr(AARCH64_IMAGE, VDSO_SIGRETURN_SYMBOL)
            .expect("the restorer is a defined dynamic symbol");
        assert!(at > 0, "a defined symbol has a real image address");
    }

    /// A name the image does not export resolves to nothing rather than to
    /// some other symbol's address.
    #[test]
    fn a_name_the_image_does_not_export_resolves_to_nothing() {
        assert_eq!(dynsym_vaddr(AARCH64_IMAGE, b"__kernel_not_a_symbol"), None);
        assert_eq!(dynsym_vaddr(AARCH64_IMAGE, b""), None);
        // The x86_64 image exposes no kernel-owned restorer at all.
        assert_eq!(dynsym_vaddr(X86_64_IMAGE, VDSO_SIGRETURN_SYMBOL), None);
    }

    /// Every offset this walk follows is read out of the image it is walking,
    /// so a truncated or corrupt image must be refused at each step rather
    /// than indexing past the end.
    #[test]
    fn a_truncated_or_corrupt_image_is_refused_rather_than_indexed_past() {
        for take in [0usize, 1, 8, 39, 40, 57, 61, 64, 128, 512] {
            let short = &AARCH64_IMAGE[..take.min(AARCH64_IMAGE.len())];
            let _ = dynsym_vaddr(short, VDSO_SIGRETURN_SYMBOL);
        }
        // A section-header offset that points past the end.
        let mut bad = AARCH64_IMAGE.to_vec();
        bad[ELF_SHOFF..ELF_SHOFF + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(dynsym_vaddr(&bad, VDSO_SIGRETURN_SYMBOL), None);
        // A section-header count that cannot fit in the image.
        let mut bad = AARCH64_IMAGE.to_vec();
        bad[ELF_SHNUM..ELF_SHNUM + 2].copy_from_slice(&u16::MAX.to_le_bytes());
        assert_eq!(dynsym_vaddr(&bad, VDSO_SIGRETURN_SYMBOL), None);
        // A section-header entry size below the layout it is about to read.
        let mut bad = AARCH64_IMAGE.to_vec();
        bad[ELF_SHENTSIZE..ELF_SHENTSIZE + 2].copy_from_slice(&1u16.to_le_bytes());
        assert_eq!(dynsym_vaddr(&bad, VDSO_SIGRETURN_SYMBOL), None);
    }
}
