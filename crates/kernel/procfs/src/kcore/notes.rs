// The note segment `/proc/kcore` carries.
//
// A note is a 12-byte header (`n_namesz`, `n_descsz`, `n_type`), the name
// including its NUL, padded to 4, then the descriptor, padded to 4. The padding
// is the part that goes wrong silently: a reader walks the segment by adding
// those lengths, so one unpadded note does not corrupt itself — it corrupts
// every note AFTER it, and the core-information note is the last one.
//
// The core-information note is why this segment exists. It is the only place a
// consumer learns where this kernel's text begins, and it is plain `KEY=value`
// text so a consumer that does not recognise a key can skip the line.

extern crate alloc;
use alloc::vec::Vec;

/// Name every process note carries.
pub const NAME_CORE: &str = "CORE";
/// Name of the core-information note.
pub const NAME_COREINFO: &str = "VMCOREINFO";

/// Note types. The process-status and process-information notes are the two a
/// core file always carries; the core-information note is type zero under its
/// own name, so the name is what identifies it.
pub const NT_PRSTATUS: u32 = 1;
/// See [`NT_PRSTATUS`].
pub const NT_PRPSINFO: u32 = 3;
/// See [`NT_PRSTATUS`].
pub const NT_COREINFO: u32 = 0;

/// Fixed note-header size: three 4-byte lengths.
pub const NHDR_SIZE: usize = 12;

/// Process-status descriptor size. The register set it ends with is
/// arch-defined, so the whole descriptor is too — a consumer reads the
/// registers at a fixed offset from the descriptor's start and takes the rest
/// of the segment from `n_descsz`.
pub const PRSTATUS_SIZE_X86_64: usize = 336;
/// See [`PRSTATUS_SIZE_X86_64`].
pub const PRSTATUS_SIZE_AARCH64: usize = 392;

/// Process-information descriptor size. Identical on both target arches.
pub const PRPSINFO_SIZE: usize = 136;

/// `pr_sname` offset and the running-state code stored there.
const PRPSINFO_SNAME_OFF: usize = 1;
/// State code for a runnable subject.
pub const STATE_RUNNING: u8 = b'R';
/// `pr_fname` offset and capacity (the last byte stays NUL).
const PRPSINFO_FNAME_OFF: usize = 40;
/// See [`PRPSINFO_SIZE`].
pub const PRPSINFO_FNAME_LEN: usize = 16;
/// `pr_psargs` offset and capacity.
const PRPSINFO_PSARGS_OFF: usize = 56;
/// See [`PRPSINFO_SIZE`].
pub const PRPSINFO_PSARGS_LEN: usize = 80;

/// The name this file reports as the subject of the core.
pub const SUBJECT_NAME: &[u8] = b"vmlinux";

/// Round a note's running length up to the 4-byte boundary the next field
/// starts on. # C: O(1)
pub fn align4(n: usize) -> usize { (n + 3) & !3 }

/// Append one note. # C: O(len name + len desc)
pub fn append(out: &mut Vec<u8>, name: &str, ty: u32, desc: &[u8]) {
    let namesz = name.len() + 1;
    out.extend_from_slice(&(namesz as u32).to_le_bytes());
    out.extend_from_slice(&(desc.len() as u32).to_le_bytes());
    out.extend_from_slice(&ty.to_le_bytes());
    out.extend_from_slice(name.as_bytes());
    out.push(0);
    pad4(out);
    out.extend_from_slice(desc);
    pad4(out);
}

fn pad4(out: &mut Vec<u8>) { while out.len() % 4 != 0 { out.push(0); } }

/// The process-information descriptor: a running subject named
/// [`SUBJECT_NAME`], whose arguments are this boot's command line. Both text
/// fields are truncated to their capacity and always NUL-terminated — a name
/// that filled its field would be read past its end.
/// # C: O(len args)
pub fn prpsinfo(args: &[u8]) -> Vec<u8> {
    let mut d = alloc::vec![0u8; PRPSINFO_SIZE];
    d[PRPSINFO_SNAME_OFF] = STATE_RUNNING;
    copy_str(&mut d[PRPSINFO_FNAME_OFF..PRPSINFO_FNAME_OFF + PRPSINFO_FNAME_LEN], SUBJECT_NAME);
    copy_str(&mut d[PRPSINFO_PSARGS_OFF..PRPSINFO_PSARGS_OFF + PRPSINFO_PSARGS_LEN], args);
    d
}

fn copy_str(dst: &mut [u8], src: &[u8]) {
    let n = src.len().min(dst.len() - 1);
    dst[..n].copy_from_slice(&src[..n]);
}

/// The core-information descriptor: the lines a consumer needs to locate this
/// kernel's text and size its pages.
/// # C: O(len osrelease)
pub fn coreinfo(osrelease: &str, page_size: u64, text_vaddr: u64) -> Vec<u8> {
    alloc::format!("OSRELEASE={osrelease}\nPAGESIZE={page_size}\nSYMBOL(_stext)={text_vaddr:x}\n")
        .into_bytes()
}

/// The whole note segment.
///
/// The process-status descriptor is all zeroes: this file describes a kernel
/// that is still running, so there is no stopped register set to report, and a
/// fabricated one would be read as the state of a CPU. Its SIZE is still the
/// arch's, because a consumer walks past it by that length.
/// # C: O(len args + len osrelease)
pub fn segment(prstatus_size: usize, args: &[u8], osrelease: &str, page_size: u64,
    text_vaddr: u64) -> Vec<u8>
{
    let mut out = Vec::new();
    append(&mut out, NAME_CORE, NT_PRSTATUS, &alloc::vec![0u8; prstatus_size]);
    append(&mut out, NAME_CORE, NT_PRPSINFO, &prpsinfo(args));
    append(&mut out, NAME_COREINFO, NT_COREINFO,
        &coreinfo(osrelease, page_size, text_vaddr));
    out
}

#[cfg(test)]
#[path = "tests/notes.rs"]
mod tests;
