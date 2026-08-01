// Two-pass layout of the image: size everything, then emit it.
//
// Pass one settles the note segment's length and where the memory half starts,
// because a program header has to name a file offset that pass two must land
// its bytes on exactly. Every offset the header table publishes is therefore
// computed before a single byte of memory is read.

use alloc::vec::Vec;

use super::input::{
    CoreImageError, CoreImageInput, CoreMem, CoreSegment, SEG_EXEC, SEG_READ, SEG_WRITE,
};
use super::layout::{SH_INFO_OFF, SH_LINK_OFF, SH_SIZE_OFF, SH_TYPE_OFF};
use super::notes;
use super::uapi::{
    EHDR64_BYTES, EI_CLASS, EI_DATA, EI_NIDENT, EI_OSABI, EI_VERSION, ELFCLASS64, ELFDATA2LSB,
    ELFOSABI_SYSV, ELF_MAGIC, ET_CORE, EV_CURRENT, NOTE_NAME_CORE, NOTE_PHDR_ALIGN, NT_PRSTATUS,
    PF_R, PF_W, PF_X, PHDR64_BYTES, PN_XNUM, PT_LOAD, PT_NOTE, SHDR64_BYTES, SHN_UNDEF,
    SHT_NULL, SIGINFO_NOTE_BYTES,
};

/// Page granularity the memory half of a dump is aligned and read in, and the
/// unit `NT_FILE` expresses mapping offsets in.
pub const CORE_PAGE_SIZE: u64 = 4096;

/// Version word of the ELF header, distinct from the `e_ident` byte.
const E_VERSION: u32 = 1;

/// Sections a core file carries when it needs the extended-numbering escape:
/// the one at index 0 whose `sh_info` holds the real program-header count.
const EXTNUM_SHNUM: u16 = 1;

fn round_up_u64(v: u64, align: u64) -> u64 { (v + align - 1) / align * align }

fn seg_flags(prot: u32) -> u32 {
    let mut f = 0;
    if prot & SEG_READ  != 0 { f |= PF_R }
    if prot & SEG_WRITE != 0 { f |= PF_W }
    if prot & SEG_EXEC  != 0 { f |= PF_X }
    f
}

fn check(input: &CoreImageInput<'_>) -> Result<(), CoreImageError> {
    if input.threads.is_empty() { return Err(CoreImageError::NoThreads) }
    let greg = input.arch.gregset_bytes();
    let fpreg = input.arch.fpregset_bytes();
    for t in input.threads.iter() {
        if t.regs.len() != greg { return Err(CoreImageError::RegsLen) }
        if let Some(fp) = t.fpregs { if fp.len() != fpreg { return Err(CoreImageError::FpregsLen) } }
    }
    if let Some(si) = input.siginfo {
        if si.len() != SIGINFO_NOTE_BYTES { return Err(CoreImageError::SiginfoLen) }
    }
    for s in input.segments.iter() {
        if s.end < s.start { return Err(CoreImageError::SegmentRange) }
        if s.start % CORE_PAGE_SIZE != 0 || s.end % CORE_PAGE_SIZE != 0 {
            return Err(CoreImageError::SegmentAlign)
        }
        if s.dump_size > s.memsz() { return Err(CoreImageError::SegmentDumpSize) }
    }
    Ok(())
}

/// Note segment, in the order a debugger reads it: the crashing thread's
/// registers, the process-wide notes, that thread's remaining state, then the
/// other threads.
fn build_notes(input: &CoreImageInput<'_>) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    let Some((first, rest)) = input.threads.split_first() else { return buf };
    notes::push_note(
        &mut buf, NOTE_NAME_CORE, NT_PRSTATUS,
        &notes::prstatus(input.arch, &input.identity, first),
    );
    notes::push_process_notes(
        &mut buf, &input.identity, input.auxv, input.siginfo, CORE_PAGE_SIZE, input.segments,
    );
    notes::push_fp_notes(&mut buf, first);
    for t in rest.iter() { notes::push_thread_notes(&mut buf, input.arch, &input.identity, t) }
    buf
}

fn push_ehdr(buf: &mut Vec<u8>, machine: u16, phnum: u16, shoff: u64) {
    let mut ident = [0u8; EI_NIDENT];
    ident[..ELF_MAGIC.len()].copy_from_slice(&ELF_MAGIC);
    ident[EI_CLASS]   = ELFCLASS64;
    ident[EI_DATA]    = ELFDATA2LSB;
    ident[EI_VERSION] = EV_CURRENT;
    ident[EI_OSABI]   = ELFOSABI_SYSV;
    buf.extend_from_slice(&ident);
    buf.extend_from_slice(&ET_CORE.to_le_bytes());
    buf.extend_from_slice(&machine.to_le_bytes());
    buf.extend_from_slice(&E_VERSION.to_le_bytes());
    buf.extend_from_slice(&0u64.to_le_bytes());                    // e_entry
    buf.extend_from_slice(&(EHDR64_BYTES as u64).to_le_bytes());   // e_phoff
    buf.extend_from_slice(&shoff.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());                    // e_flags
    buf.extend_from_slice(&(EHDR64_BYTES as u16).to_le_bytes());
    buf.extend_from_slice(&(PHDR64_BYTES as u16).to_le_bytes());
    buf.extend_from_slice(&phnum.to_le_bytes());
    let extnum = shoff != 0;
    let shentsize = if extnum { SHDR64_BYTES as u16 } else { 0 };
    let shnum = if extnum { EXTNUM_SHNUM } else { 0 };
    buf.extend_from_slice(&shentsize.to_le_bytes());
    buf.extend_from_slice(&shnum.to_le_bytes());
    buf.extend_from_slice(&SHN_UNDEF.to_le_bytes());
}

#[allow(clippy::too_many_arguments)]
fn push_phdr(
    buf: &mut Vec<u8>, ty: u32, flags: u32, offset: u64, vaddr: u64, filesz: u64, memsz: u64,
    align: u64,
) {
    buf.extend_from_slice(&ty.to_le_bytes());
    buf.extend_from_slice(&flags.to_le_bytes());
    buf.extend_from_slice(&offset.to_le_bytes());
    buf.extend_from_slice(&vaddr.to_le_bytes());
    buf.extend_from_slice(&0u64.to_le_bytes());                    // p_paddr
    buf.extend_from_slice(&filesz.to_le_bytes());
    buf.extend_from_slice(&memsz.to_le_bytes());
    buf.extend_from_slice(&align.to_le_bytes());
}

/// The section header the extended-numbering escape publishes the real program
/// header count in.
fn push_extnum_shdr(buf: &mut Vec<u8>, phdr_count: u64) {
    let mut shdr = [0u8; SHDR64_BYTES];
    shdr[SH_TYPE_OFF..SH_TYPE_OFF + 4].copy_from_slice(&SHT_NULL.to_le_bytes());
    shdr[SH_SIZE_OFF..SH_SIZE_OFF + 8].copy_from_slice(&(EXTNUM_SHNUM as u64).to_le_bytes());
    shdr[SH_LINK_OFF..SH_LINK_OFF + 4].copy_from_slice(&(SHN_UNDEF as u32).to_le_bytes());
    shdr[SH_INFO_OFF..SH_INFO_OFF + 4].copy_from_slice(&(phdr_count as u32).to_le_bytes());
    buf.extend_from_slice(&shdr);
}

fn push_segment_data<M: CoreMem>(buf: &mut Vec<u8>, seg: &CoreSegment<'_>, mem: &mut M) {
    let mut done: u64 = 0;
    while done < seg.dump_size {
        let want = (seg.dump_size - done).min(CORE_PAGE_SIZE) as usize;
        let at = buf.len();
        buf.resize(at + want, 0);
        let got = mem.read(seg.start + done, &mut buf[at..at + want]).min(want);
        // A hole stays zero-filled: the program header already promised these
        // bytes, so shortening the write would desynchronise every later offset.
        for b in buf[at + got..at + want].iter_mut() { *b = 0 }
        done += want as u64;
    }
}

/// Assemble the `ET_CORE` image for a dying process.
///
/// Contents of every dumped mapping are pulled through `mem`; a mapping it
/// cannot produce becomes zeroes rather than a short segment.
/// # C: O(image bytes)
pub fn build_core_image<M: CoreMem>(
    input: &CoreImageInput<'_>, mem: &mut M,
) -> Result<Vec<u8>, CoreImageError> {
    check(input)?;

    let note_blob = build_notes(input);

    // One program header for the notes, then one per mapping.
    let phdr_count = input.segments.len() as u64 + 1;
    let extnum = phdr_count >= PN_XNUM as u64;
    let e_phnum = if extnum { PN_XNUM } else { phdr_count as u16 };

    let hdrs_bytes = EHDR64_BYTES as u64 + phdr_count * PHDR64_BYTES as u64;
    let note_off = hdrs_bytes;
    let dataoff = round_up_u64(note_off + note_blob.len() as u64, CORE_PAGE_SIZE);
    let data_bytes: u64 = input.segments.iter().map(|s| s.dump_size).sum();
    let e_shoff = if extnum { dataoff + data_bytes } else { 0 };

    let total = if extnum { e_shoff + SHDR64_BYTES as u64 } else { dataoff + data_bytes };
    let mut buf: Vec<u8> = Vec::with_capacity(total as usize);

    push_ehdr(&mut buf, input.arch.machine(), e_phnum, e_shoff);
    push_phdr(&mut buf, PT_NOTE, 0, note_off, 0, note_blob.len() as u64, 0, NOTE_PHDR_ALIGN);
    let mut off = dataoff;
    for s in input.segments.iter() {
        push_phdr(
            &mut buf, PT_LOAD, seg_flags(s.prot), off, s.start, s.dump_size, s.memsz(),
            CORE_PAGE_SIZE,
        );
        off += s.dump_size;
    }
    hal::kassert!(buf.len() as u64 == hdrs_bytes, "header table length matches its plan");

    buf.extend_from_slice(&note_blob);
    buf.resize(dataoff as usize, 0);
    for s in input.segments.iter() { push_segment_data(&mut buf, s, mem) }
    hal::kassert!(buf.len() as u64 == dataoff + data_bytes, "memory half lands where planned");

    if extnum { push_extnum_shdr(&mut buf, phdr_count) }
    Ok(buf)
}
