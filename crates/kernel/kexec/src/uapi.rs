// kexec(2) UAPI: flag bits, architecture tags, the segment record and the
// relocation-list entry encoding. Numbers only — every decision lives in
// `validate`, every state change in `image` / `store`.

/// `KEXEC_ON_CRASH`: the image is a crash kernel, staged into the reserved
/// crash region and started from the panic path rather than from `reboot(2)`.
pub const KEXEC_ON_CRASH: u64 = 0x0000_0001;
/// `KEXEC_PRESERVE_CONTEXT`: return to THIS kernel after the loaded image runs
/// (`kexec jump`). Legal only where `CONFIG_KEXEC_JUMP` is built.
pub const KEXEC_PRESERVE_CONTEXT: u64 = 0x0000_0002;
/// `KEXEC_UPDATE_ELFCOREHDR`.
pub const KEXEC_UPDATE_ELFCOREHDR: u64 = 0x0000_0004;
/// `KEXEC_CRASH_HOTPLUG_SUPPORT`.
pub const KEXEC_CRASH_HOTPLUG_SUPPORT: u64 = 0x0000_0008;
/// `KEXEC_ARCH_MASK`: the high half of `flags` carries an ELF machine number.
pub const KEXEC_ARCH_MASK: u64 = 0xffff_0000;

/// `KEXEC_ARCH_DEFAULT`: "whatever this kernel is".
pub const KEXEC_ARCH_DEFAULT: u64 = 0 << 16;
/// `KEXEC_ARCH_386` — `EM_386`.
pub const KEXEC_ARCH_386: u64 = 3 << 16;
/// `KEXEC_ARCH_X86_64` — `EM_X86_64`.
pub const KEXEC_ARCH_X86_64: u64 = 62 << 16;
/// `KEXEC_ARCH_ARM` — `EM_ARM`.
pub const KEXEC_ARCH_ARM: u64 = 40 << 16;
/// `KEXEC_ARCH_AARCH64` — `EM_AARCH64`.
pub const KEXEC_ARCH_AARCH64: u64 = 183 << 16;

/// The architecture tag this build accepts alongside `KEXEC_ARCH_DEFAULT`.
/// A 32-bit `KEXEC_ARCH_386` image is refused on x86_64 exactly as the
/// reference refuses it: `KEXEC_ARCH` is the *native* machine, and the compat
/// entry point is the only place a foreign tag is even considered.
#[cfg(target_arch = "aarch64")]
pub const KEXEC_ARCH: u64 = KEXEC_ARCH_AARCH64;
/// See the aarch64 arm.
#[cfg(not(target_arch = "aarch64"))]
pub const KEXEC_ARCH: u64 = KEXEC_ARCH_X86_64;

/// Legal `kexec_load` flag set outside the architecture field.
///
/// `KEXEC_PRESERVE_CONTEXT` is NOT a member. It is gated on `CONFIG_KEXEC_JUMP`
/// upstream — an option that exists on x86 only and is unset in the
/// configuration this port targets, and whose contract (suspend devices, run
/// the loaded image, resume THIS kernel) has no implementation here. Accepting
/// the bit and ignoring it would turn "come back afterwards" into "never come
/// back", which is worse than the EINVAL a jump-less kernel already returns.
pub const KEXEC_FLAGS: u64 =
    KEXEC_ON_CRASH | KEXEC_UPDATE_ELFCOREHDR | KEXEC_CRASH_HOTPLUG_SUPPORT;

/// `KEXEC_FILE_UNLOAD`: drop the staged image; ignore the fds.
pub const KEXEC_FILE_UNLOAD: u64 = 0x0000_0001;
/// `KEXEC_FILE_ON_CRASH`: the file-mode spelling of `KEXEC_ON_CRASH`.
pub const KEXEC_FILE_ON_CRASH: u64 = 0x0000_0002;
/// `KEXEC_FILE_NO_INITRAMFS`: `initrd_fd` is not read and need not be valid.
pub const KEXEC_FILE_NO_INITRAMFS: u64 = 0x0000_0004;
/// `KEXEC_FILE_DEBUG`: trace the load.
pub const KEXEC_FILE_DEBUG: u64 = 0x0000_0008;
/// `KEXEC_FILE_NO_CMA`: never place segments in CMA.
pub const KEXEC_FILE_NO_CMA: u64 = 0x0000_0010;
/// `KEXEC_FILE_FORCE_DTB`: carry this boot's DTB to the loaded kernel.
pub const KEXEC_FILE_FORCE_DTB: u64 = 0x0000_0020;

/// Legal `kexec_file_load` flag set. Unlike `kexec_load` there is no
/// architecture field, so the test is exact equality.
pub const KEXEC_FILE_FLAGS: u64 = KEXEC_FILE_UNLOAD
    | KEXEC_FILE_ON_CRASH
    | KEXEC_FILE_NO_INITRAMFS
    | KEXEC_FILE_DEBUG
    | KEXEC_FILE_NO_CMA
    | KEXEC_FILE_FORCE_DTB;

/// `KEXEC_SEGMENT_MAX`: the artificial cap on `nr_segments`.
pub const KEXEC_SEGMENT_MAX: u64 = 16;

/// Largest kernel / initrd file `kexec_file_load` will read, `min(4 GiB,
/// SSIZE_MAX)`.
pub const KEXEC_FILE_SIZE_MAX: u64 = 4 << 30;

/// Page size the relocation list is expressed in. kexec is defined in terms of
/// the boot-time page granule on both arches this port builds.
pub const PAGE_SIZE: u64 = 4096;
/// Mask selecting the page-frame bits of a relocation entry.
pub const PAGE_MASK: u64 = !(PAGE_SIZE - 1);

/// Bytes of control code the arch trampoline is copied into.
pub const KEXEC_CONTROL_PAGE_SIZE: u64 = 4096;

/// `IND_DESTINATION`: the entry carries the physical address the following
/// source pages are copied to.
pub const IND_DESTINATION: u64 = 1 << 0;
/// `IND_INDIRECTION`: the entry points at the next page of relocation entries.
pub const IND_INDIRECTION: u64 = 1 << 1;
/// `IND_DONE`: end of the relocation list.
pub const IND_DONE: u64 = 1 << 2;
/// `IND_SOURCE`: the entry carries a page to copy to the running destination.
pub const IND_SOURCE: u64 = 1 << 3;
/// Every defined relocation-entry flag.
pub const IND_FLAGS: u64 = IND_DESTINATION | IND_INDIRECTION | IND_DONE | IND_SOURCE;

/// Relocation-list entries per page.
pub const ENTRIES_PER_PAGE: usize = (PAGE_SIZE / 8) as usize;

/// Image kind. `KEXEC_TYPE_DEFAULT` boots from `reboot(2)`;
/// `KEXEC_TYPE_CRASH` boots from the panic path out of reserved memory.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ImageType { Default, Crash }

/// One `struct kexec_segment`. `buf`/`mem` are addresses, not pointers: the
/// source is a user address in `kexec_load` and a kernel buffer offset in
/// `kexec_file_load`, and only the loader knows which.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct KexecSegment {
    /// Source buffer address (user VA, or kernel buffer in file mode).
    pub buf: u64,
    /// Bytes readable at `buf`.
    pub bufsz: u64,
    /// Destination physical address; page aligned.
    pub mem: u64,
    /// Bytes reserved at `mem`; page aligned and `>= bufsz`.
    pub memsz: u64,
}

/// Bytes one `struct kexec_segment` occupies in the 64-bit ABI.
pub const KEXEC_SEGMENT_SIZE: usize = 32;

impl KexecSegment {
    /// Decode one segment from its 64-bit ABI representation.
    /// # C: O(1)
    pub fn from_bytes(raw: &[u8; KEXEC_SEGMENT_SIZE]) -> Self {
        let rd = |o: usize| -> u64 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&raw[o..o + 8]);
            u64::from_le_bytes(b)
        };
        Self { buf: rd(0), bufsz: rd(8), mem: rd(16), memsz: rd(24) }
    }
}

/// Pages a byte count spans, rounding up (`PAGE_COUNT`).
/// # C: O(1)
pub fn page_count(bytes: u64) -> u64 { bytes.div_ceil(PAGE_SIZE) }
