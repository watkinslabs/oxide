// ELF loader glue per docs/31§4.
//
// Drives `crates/elf::parse` against a `&'static [u8]` blob and
// registers each PT_LOAD as a MAP_FIXED VMA in the supplied
// `AddressSpace` with `VmaBacking::KernelBytes` (P2-17). Returns
// the entry-point VA the caller drops to user mode at.
//
// v1 scope (no VFS, no ld.so):
//  - blob is `&'static [u8]` baked into the kernel image; future
//    callers (execve via VFS) will pass a freshly-read inode page
//    instead.
//  - `ET_DYN` (PIE) is loaded at its declared `p_vaddr` — no
//    `load_bias` randomisation yet (`31§6` ASLR is v1.x).
//  - PT_INTERP / PT_TLS / PT_DYNAMIC are parsed but not acted on.
//  - Stack + auxv build is the smoke driver's responsibility for
//    now; the loader only places the executable image.

#![no_std]

extern crate alloc;

use elf::{parse, ElfError, EM_X86_64};
#[cfg(target_arch = "aarch64")]
use elf::EM_AARCH64;
use hal::UserVirtAddr;
use vmm::{AddressSpace, VmaProt};

mod load;

const PAGE: u64 = hal::PAGE_SIZE_BYTES;

/// The current-arch `e_machine` per `31§2` invariant 1.
#[cfg(target_arch = "x86_64")]
pub const ARCH_MACHINE: u16 = EM_X86_64;
#[cfg(target_arch = "aarch64")]
pub const ARCH_MACHINE: u16 = EM_AARCH64;

/// Loader error — surfaces ENOEXEC for invariant violations and
/// ENOMEM for mmap failures, matching docs/31§9.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum LoadError {
    Enoexec,
    Einval,
    Enomem,
}

impl From<ElfError> for LoadError {
    fn from(e: ElfError) -> Self {
        match e {
            ElfError::Enoexec    => LoadError::Enoexec,
            ElfError::Einval     => LoadError::Einval,
            ElfError::Eopnotsupp => LoadError::Einval,
        }
    }
}

/// Result of a successful load — caller drops to user mode at
/// `interp_entry` if non-zero (PT_INTERP path), otherwise at
/// `entry`. The auxv build (`exec_stack`) carries `interp_base`
/// in AT_BASE so the dynamic linker can locate itself.
#[derive(Copy, Clone, Debug)]
pub struct LoadedImage {
    /// The exec's own e_entry, biased by PIE_LOAD_BIAS for ET_DYN.
    /// Becomes auxv AT_ENTRY; the dynamic linker hands control here
    /// after loading DT_NEEDED. Static-PIE binaries jump here directly.
    pub entry:      UserVirtAddr,
    pub brk:        UserVirtAddr,
    /// User VA where the program-header table lives. Computed by
    /// finding the PT_LOAD whose file range covers `e_phoff` and
    /// translating: `phdr_va = seg.vaddr + (phoff - seg.file_off)`.
    /// Auxv AT_PHDR per `31§4`. `0` if no PT_LOAD covers phoff.
    pub phdr_va:    u64,
    pub phentsize:  u16,
    pub phnum:      u16,
    /// Load base of the dynamic-linker (PT_INTERP) image, or `0`
    /// if no interpreter was requested. Auxv AT_BASE per `31§4`.
    pub interp_base: u64,
    /// Entry-point of the dynamic linker, or `0` if no interpreter.
    /// `spawn_user_blob_smoke` / `sys_execve` drop to ring 3 here
    /// when non-zero so the linker runs first; the linker reads
    /// AT_ENTRY to find the exec's actual entry.
    pub interp_entry: u64,
    /// Linux `mm->start_code`..`end_data`: page-aligned bounds of the
    /// first executable PT_LOAD (code) and first writable PT_LOAD
    /// (data). Fed to `AddressSpace::set_code_data` so `/proc/<pid>/stat`
    /// fields 26/27/45/46 and `prctl(PR_SET_MM)` validation are correct.
    /// `0` when the image lacks a segment of that kind.
    pub start_code: u64,
    pub end_code:   u64,
    pub start_data: u64,
    pub end_data:   u64,
}

impl LoadedImage {
    /// User RIP to drop into ring 3: the dynamic linker if PT_INTERP
    /// was set, else the exec's own entry (static-PIE / static path).
    /// # C: O(1)
    pub fn user_ip(&self) -> u64 {
        if self.interp_entry != 0 { self.interp_entry } else { self.entry.as_u64() }
    }
}

/// Read the dynamic-linker (PT_INTERP) file from the rootfs and
/// return an owned `Vec<u8>`. Caller drops it after `place_image`
/// has copied the segment bytes into AS-owned staging buffers
/// (per B22) — no per-exec leak.
/// # SAFETY: caller is the ELF loader; ext4 mount has been brought
/// up by `kernel_main` before any execve runs.
/// # C: O(file size) — one ext4 read.
#[cfg(target_os = "oxide-kernel")]
fn read_interp_blob(path: &[u8]) -> Option<alloc::vec::Vec<u8>> {
    if let Some(blob) = ext4::rootfs::read_file(path) {
        return Some(blob);
    }
    // The early interpreter reader still uses the raw ext4 rootfs helper,
    // which does not follow intermediate symlinks. Fedora-style merged-/usr
    // roots commonly expose `/lib` and `/lib64` as symlinks into `/usr`.
    if let Some(rest) = path.strip_prefix(b"/lib64/") {
        let mut p = alloc::vec::Vec::with_capacity(b"/usr/lib64/".len() + rest.len());
        p.extend_from_slice(b"/usr/lib64/");
        p.extend_from_slice(rest);
        return ext4::rootfs::read_file(&p);
    }
    if let Some(rest) = path.strip_prefix(b"/lib/") {
        let mut p = alloc::vec::Vec::with_capacity(b"/usr/lib/".len() + rest.len());
        p.extend_from_slice(b"/usr/lib/");
        p.extend_from_slice(rest);
        return ext4::rootfs::read_file(&p);
    }
    None
}

#[cfg(not(target_os = "oxide-kernel"))]
fn read_interp_blob(_path: &[u8]) -> Option<alloc::vec::Vec<u8>> { None }

/// Default load bias for ET_DYN (PIE) images. Real Linux
/// randomises this per-exec; v1 uses a fixed value disjoint from
/// the hand-rolled-blob VAs (0x400000) and from the user stack
/// (0x501000). 0x10000000 keeps the user-half plenty of room.
/// docs/31§6 ASLR is v1.x — fixed bias for now.
const PIE_LOAD_BIAS: u64 = 0x1000_0000;

/// Load bias for the dynamic-linker (PT_INTERP) image. Disjoint
/// from `PIE_LOAD_BIAS` + the 64 MiB heap above the exec so the
/// linker's PT_LOADs never collide with the exec's heap window.
/// Real Linux randomises this; v1 fixed.
const INTERP_LOAD_BIAS: u64 = 0x4000_0000;

/// Load `blob` into `as_` per docs/31§4. Each PT_LOAD becomes a
/// MAP_FIXED VMA with `VmaBacking::KernelBytes` (P2-17) so demand-
/// paging copies the bytes from the kernel image on first touch.
///
/// PIE binaries (`ET_DYN`) get the fixed `PIE_LOAD_BIAS`; non-PIE
/// (`ET_EXEC`) load at their declared `p_vaddr`. All `entry`,
/// `phdr_va`, `brk`, and stack VAs are biased accordingly.
///
/// `blob` only needs to live for the duration of this call: the
/// segment bytes are copied into AS-owned staging Vecs (B22), so
/// the input slice can be a transient `&Vec<u8>` from an ext4 read
/// or a `&'static` const-blob — both work.
///
struct LoadStaging {
    vstart:   u64,
    vend:     u64,
    prot:     VmaProt,
    padded:   alloc::vec::Vec<u8>,
    head_pad: usize,
}

/// # C: O(phdrs) parse + O(phdrs) mmap
pub fn load_static_blob(
    blob: &[u8],
    as_: &AddressSpace,
) -> Result<LoadedImage, LoadError> {
    // Two cases per Linux execve:
    //   * No PT_INTERP (static, static-PIE): the kernel is the
    //     only thing that runs before user `_start`, so we apply
    //     R_*_RELATIVE self-relocs to the exec image now.
    //   * PT_INTERP present (dynamic): musl's `_dlstart` self-
    //     relocates the loader, then walks the exec's PT_DYNAMIC
    //     and applies its relocs. Kernel pre-application would
    //     be a DOUBLE-relocation — every R_RELATIVE entry would
    //     be biased twice and the program crashes. Skip pre-reloc
    //     on both images in this case.
    let exec_parsed = parse(blob, ARCH_MACHINE)?;
    let has_interp = exec_parsed.interp.is_some();
    let exec = place_image(blob, as_, None, !has_interp)?;

    let parsed = exec_parsed;
    let mut interp_base: u64 = 0;
    let mut interp_entry: u64 = 0;
    if let Some(interp_path) = parsed.interp {
        #[cfg(feature = "debug-boot")]
        {
            klog::write_raw(b"[INFO]  elf-load: interp ");
            klog::write_raw(interp_path);
            klog::write_raw(b"\n");
        }
        let interp_blob = match read_interp_blob(interp_path) {
            Some(blob) => {
                #[cfg(feature = "debug-boot")]
                klog::write_raw(b"[INFO]  elf-load: interp read ok\n");
                blob
            }
            None => {
                #[cfg(feature = "debug-boot")]
                klog::write_raw(b"[ERROR] elf-load: interp read failed\n");
                return Err(LoadError::Enoexec);
            }
        };
        let interp = match place_image(&interp_blob, as_, Some(INTERP_LOAD_BIAS), false) {
            Ok(img) => {
                #[cfg(feature = "debug-boot")]
                klog::write_raw(b"[INFO]  elf-load: interp place ok\n");
                img
            }
            Err(err) => {
                #[cfg(feature = "debug-boot")]
                {
                    klog::write_raw(b"[ERROR] elf-load: interp place failed err=");
                    klog::write_raw(load_error_name(err));
                    klog::write_raw(b"\n");
                }
                return Err(err);
            }
        };
        interp_base  = INTERP_LOAD_BIAS;
        interp_entry = interp.entry.as_u64();
    }

    Ok(LoadedImage {
        entry:        exec.entry,
        brk:          exec.brk,
        phdr_va:      exec.phdr_va,
        phentsize:    exec.phentsize,
        phnum:        exec.phnum,
        interp_base,
        interp_entry,
        // Code/data bounds come from the EXEC image, never the interp.
        start_code:   exec.start_code,
        end_code:     exec.end_code,
        start_data:   exec.start_data,
        end_data:     exec.end_data,
    })
}

#[cfg(feature = "debug-boot")]
fn load_error_name(err: LoadError) -> &'static [u8] {
    match err {
        LoadError::Enoexec => b"Enoexec",
        LoadError::Einval => b"Einval",
        LoadError::Enomem => b"Enomem",
    }
}

use load::place_image;


#[cfg(target_os = "oxide-kernel")] pub mod stack;
