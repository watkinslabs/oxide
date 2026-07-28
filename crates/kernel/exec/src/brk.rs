// Where the heap starts. Linux `load_elf_binary` (`fs/binfmt_elf.c:1310-1342`).

use aslr::ExecRnd;
use elf::ElfType;
use hal::UserVirtAddr;
use vmm::{AddressSpace, VmaBacking, VmaFlags, VmaProt};

use crate::LoadError;

/// VA reserved above `start_brk` for `brk(2)` to grow into. Linux maps nothing
/// here and extends the heap VMA on demand; this kernel pre-maps the window
/// and `try_set_brk` clamps inside it.
const HEAP_RESERVE: u64 = 64 * 1024 * 1024;

/// Place `mm->start_brk`/`mm->brk` and map the window `brk(2)` grows into.
/// Returns the new `start_brk`.
///
/// Two Linux behaviours ride here. A PIE with no interpreter has its image
/// placed by the arena search, so leaving the heap directly above it would put
/// the heap inside the mmap arena; Linux moves it to `ELF_ET_DYN_BASE` instead
/// (`:1310-1315`, the `brk_moved` flag). Then, when the heap randomises, an
/// image whose heap was NOT moved first steps one page clear of the image end
/// (`:1334-1335`) so `start_brk` can never alias the last data page.
/// # C: O(N) VMA insert
pub(crate) fn install(
    as_: &AddressSpace,
    elf_type: ElfType,
    has_interp: bool,
    image_end: u64,
    rnd: &ExecRnd,
) -> Result<u64, LoadError> {
    let moved = elf_type == ElfType::Dyn && !has_interp;
    let elf_brk = if moved { aslr::ELF_ET_DYN_BASE } else { image_end };
    let start_brk = rnd.brk(elf_brk, moved);

    let end = start_brk.checked_add(HEAP_RESERVE).ok_or(LoadError::Einval)?;
    let hint = UserVirtAddr::new(start_brk).ok_or(LoadError::Einval)?;
    if UserVirtAddr::new(end).is_none() { return Err(LoadError::Einval); }
    as_.mmap(
        Some(hint),
        HEAP_RESERVE as usize,
        VmaProt::READ | VmaProt::WRITE,
        VmaFlags::PRIVATE | VmaFlags::ANONYMOUS,
        VmaBacking::Anonymous,
        true,
    )
    .map_err(|_| LoadError::Enomem)?;
    as_.set_brk_window(start_brk, end);
    Ok(start_brk)
}
