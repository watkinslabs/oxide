// ELF loader glue per docs/31§4.
//
// Drives `crates/elf::parse` against a `&'static [u8]` blob and
// registers each PT_LOAD as a MAP_FIXED VMA in the supplied
// `AddressSpace`, backed by the file the image was read from where
// the segment is a mapping of it. Returns
// the entry-point VA the caller drops to user mode at.
//
// Module manifest:
//   `load`  — PT_LOAD placement + R_*_RELATIVE self-relocation staging.
//   `layout` — how a segment divides between its file and kernel-owned bytes.
//   `place` — the two Linux placement strategies and the phdr scans they need.
//   `brk`     — `start_brk` selection and the heap window.
//   `persona` — the `MMAP_PAGE_ZERO` SVr4 emulation at the tail of the load.
//   `stack` — initial stack, argv/envp/auxv (kernel-only).
//   `uapi`  — auxv keys.
//
// Address randomisation is `aslr::ExecRnd`, drawn once per exec by the execve
// work fn and threaded in — the loader never draws its own, so every mapping
// in one exec agrees about where the others are (`31§6`).

#![no_std]

// dead_code is meaningful for this crate ONLY on the kernel target. A large
// part of it sits behind `cfg(target_os = "oxide-kernel")`, so a host build
// (`cargo test`, `cargo check --workspace`) compiles a strict subset and calls
// hundreds of live items dead. The kernel builds keep dead_code fully enabled
// and are warning-clean, and every one of these crates links into `kmain`, so
// nothing is hidden: real dead code still surfaces on `xtask kernel`.
#![cfg_attr(not(target_os = "oxide-kernel"), allow(dead_code))]
extern crate alloc;

use elf::{parse, ElfError, ElfType};
#[cfg(target_arch = "x86_64")]
use elf::EM_X86_64;
#[cfg(target_arch = "aarch64")]
use elf::EM_AARCH64;
use hal::UserVirtAddr;
use vmm::{AddressSpace, VmaProt};

mod brk;
mod layout;
mod load;
pub mod persona;
mod place;
mod uapi;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_file_backing;

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
    /// The exec's own e_entry, biased by the ET_DYN load bias.
    /// Becomes auxv AT_ENTRY; the dynamic linker hands control here
    /// after loading DT_NEEDED. Static-PIE binaries jump here directly.
    pub entry:      UserVirtAddr,
    pub brk:        UserVirtAddr,
    /// The bias every `p_vaddr` in this image was placed at — Linux
    /// `load_bias`. `0` for ET_EXEC. The interpreter's value becomes AT_BASE.
    pub load_base:  u64,
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

/// Load `blob` into `as_` per docs/31§4. Each PT_LOAD becomes a MAP_FIXED
/// VMA; the part of it that is a mapping of the file is backed by that file,
/// the rest by kernel-owned bytes demand-paging copies on first touch.
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
    /// Kernel-owned bytes for `[file_end, vend)`. Empty when the whole
    /// segment is a mapping of its file.
    padded:   alloc::vec::Vec<u8>,
    head_pad: usize,
    file_end:   u64,
    file_pgoff: u64,
    file_zero_from: Option<u64>,
}

/// One image the loader places: its bytes, and the file they were read from.
///
/// The file is Linux `bprm->file` for the exec and the interpreter's own file
/// for a PT_INTERP image. It becomes each PT_LOAD's backing, so the program's
/// text and data are file-backed mappings. `None` is an image with no file
/// behind it — a blob linked into the kernel — whose segments are backed by
/// kernel-owned bytes.
pub struct Image<'a> {
    pub blob: &'a [u8],
    pub file: Option<alloc::sync::Arc<dyn vmm::FileBacking>>,
}

impl<'a> Image<'a> {
    /// An image the kernel carries rather than one it opened. # C: O(1)
    pub fn embedded(blob: &'a [u8]) -> Self { Self { blob, file: None } }
}

/// Opens the pathname a PT_INTERP names, yielding its bytes and its file.
/// Callers without a resolved filesystem pass `None` and the loader falls back
/// to the boot-time rootfs reader, which yields no file.
pub type InterpOpen<'a> =
    &'a dyn Fn(&[u8]) -> Option<(alloc::vec::Vec<u8>, Option<alloc::sync::Arc<dyn vmm::FileBacking>>)>;

/// `rnd` is this exec's randomisation draw. Callers that are not an execve
/// (boot smoke drivers) pass `aslr::exec::NONE` for a fixed layout.
/// # C: O(phdrs) parse + O(phdrs) mmap
pub fn load_static_blob(
    blob: &[u8],
    as_: &AddressSpace,
    rnd: &aslr::ExecRnd,
) -> Result<LoadedImage, LoadError> {
    load_image(Image::embedded(blob), None, as_, rnd)
}

/// `load_static_blob` with the files behind the images, per `31§4`.
/// # C: O(phdrs) parse + O(phdrs) mmap
pub fn load_image(
    exec_image: Image<'_>,
    interp_open: Option<InterpOpen<'_>>,
    as_: &AddressSpace,
    rnd: &aslr::ExecRnd,
) -> Result<LoadedImage, LoadError> {
    let blob = exec_image.blob;
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

    // Linux `load_elf_binary` (`fs/binfmt_elf.c:1097-1186`). ET_EXEC is
    // absolute. A PIE WITH an interpreter is the case Linux randomises
    // explicitly — `ELF_ET_DYN_BASE + arch_mmap_rnd()`. A PIE WITHOUT one
    // (static-PIE, or ld.so invoked directly) gets `load_bias = 0` and a
    // hint-0 mmap, so the arena search places it and it inherits `mmap_base`'s
    // randomisation instead of drawing its own.
    let placement = match (exec_parsed.elf_type, has_interp) {
        (ElfType::Exec, _)   => Placement::Fixed(0),
        (ElfType::Dyn, true) => Placement::Fixed(
            rnd.elf_dyn_load_bias(place::maximum_alignment(&exec_parsed.loads))),
        (ElfType::Dyn, false) => Placement::Unmapped,
        _ => return Err(LoadError::Enoexec),
    };
    let exec = place_image(blob, as_, placement, !has_interp, exec_image.file.as_ref())?;

    let parsed = exec_parsed;
    let mut interp_base: u64 = 0;
    let mut interp_entry: u64 = 0;
    if let Some(interp_path) = parsed.interp {
        #[cfg(feature = "debug-execload")]
        {
            klog::write_raw(b"[INFO]  elf-load: interp ");
            klog::write_raw(interp_path);
            klog::write_raw(b"\n");
        }
        let opened = interp_open.and_then(|open| open(interp_path));
        let (interp_blob, interp_file) = match opened {
            Some(pair) => pair,
            None => match read_interp_blob(interp_path) {
                Some(blob) => {
                    #[cfg(feature = "debug-execload")]
                    klog::write_raw(b"[INFO]  elf-load: interp read ok\n");
                    (blob, None)
                }
                None => {
                    #[cfg(feature = "debug-execload")]
                    klog::write_raw(b"[ERROR] elf-load: interp read failed\n");
                    return Err(LoadError::Enoexec);
                }
            },
        };
        let interp =
            match place_image(&interp_blob, as_, Placement::Unmapped, false, interp_file.as_ref()) {
            Ok(img) => {
                #[cfg(feature = "debug-execload")]
                klog::write_raw(b"[INFO]  elf-load: interp place ok\n");
                img
            }
            Err(err) => {
                #[cfg(feature = "debug-execload")]
                {
                    klog::write_raw(b"[ERROR] elf-load: interp place failed err=");
                    klog::write_raw(load_error_name(err));
                    klog::write_raw(b"\n");
                }
                return Err(err);
            }
        };
        interp_base  = interp.load_base;
        interp_entry = interp.entry.as_u64();
    }

    // Heap placement runs LAST, after the interpreter, exactly as Linux orders
    // it — `start_brk` depends on whether an interpreter was present.
    let start_brk = brk::install(as_, parsed.elf_type, has_interp, exec.brk.as_u64(), rnd)?;

    Ok(LoadedImage {
        entry:        exec.entry,
        brk:          UserVirtAddr::new(start_brk).ok_or(LoadError::Einval)?,
        load_base:    exec.load_base,
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

#[cfg(feature = "debug-execload")]
fn load_error_name(err: LoadError) -> &'static [u8] {
    match err {
        LoadError::Enoexec => b"Enoexec",
        LoadError::Einval => b"Einval",
        LoadError::Enomem => b"Enomem",
    }
}

use layout::relocs_precede_file_backing;
use load::place_image;
use place::Placement;


#[cfg(target_os = "oxide-kernel")] pub mod stack;

/// Publish the Linux `mm_struct` layout produced by one ELF load and its
/// initial stack build. Every exec entry path, including the kernel's PID 1
/// bootstrap, must use this single commit point so `/proc` and `PR_SET_MM`
/// observe the same canonical metadata.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn commit_mm_layout(as_: &AddressSpace, img: &LoadedImage, layout: &stack::StackLayout) {
    as_.set_code_data(img.start_code, img.end_code, img.start_data, img.end_data);
    as_.set_start_brk(img.brk.as_u64());
    as_.set_arg_env_stack(
        layout.arg_start, layout.arg_end, layout.env_start, layout.env_end, layout.sp,
    );
    as_.save_exec_auxv(&layout.auxv[..layout.auxv_len]);
}
