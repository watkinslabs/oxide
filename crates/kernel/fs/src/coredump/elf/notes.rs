// The note segment: the whole non-memory half of a core file.
//
// Order is load-bearing. A debugger takes the first `NT_PRSTATUS` as the
// crashing thread, so the dumping thread's registers lead, the process-wide
// notes follow it, and every further thread's notes come after those.

use alloc::vec::Vec;

use super::input::{CoreIdentity, CoreSegment, CoreThread};
use super::layout::{
    self, CoreArch, PR_CSTIME_OFF, PR_CURSIG_OFF, PR_CUTIME_OFF, PR_INFO_SIGNO_OFF, PR_PGRP_OFF,
    PR_PID_OFF, PR_PPID_OFF, PR_REG_OFF, PR_SID_OFF, PR_SIGHOLD_OFF, PR_SIGPEND_OFF,
    PR_STIME_OFF, PR_UTIME_OFF, PRPSINFO_BYTES, PSINFO_FLAG_OFF, PSINFO_FNAME_BYTES,
    PSINFO_FNAME_OFF, PSINFO_GID_OFF, PSINFO_NICE_OFF, PSINFO_PGRP_OFF, PSINFO_PID_OFF,
    PSINFO_PPID_OFF, PSINFO_PSARGS_BYTES, PSINFO_PSARGS_OFF, PSINFO_SID_OFF, PSINFO_SNAME_OFF,
    PSINFO_STATE_OFF, PSINFO_UID_OFF, PSINFO_ZOMB_OFF, TIMEVAL_BYTES,
};
use super::uapi::{
    NOTE_ALIGN, NOTE_HDR_BYTES, NOTE_NAME_CORE, NOTE_NAME_LINUX, NT_AUXV, NT_FILE, NT_PRFPREG,
    NT_PRPSINFO, NT_PRSTATUS, NT_SIGINFO, NT_X86_XSTATE,
};

/// Bytes of one LP64 word in the `NT_FILE` table.
const FILE_WORD_BYTES: usize = 8;

/// Words the `NT_FILE` descriptor leads with: the entry count and the page size
/// its file offsets are expressed in.
const FILE_HDR_WORDS: usize = 2;

/// Words each `NT_FILE` entry occupies: start, end, file offset in pages.
const FILE_ENTRY_WORDS: usize = 3;

/// Set when a thread carries floating-point state.
const PR_FPVALID_TRUE: i32 = 1;

/// Bytes a note occupies once its name and descriptor are padded.
/// # C: O(1)
pub fn note_bytes(name: &[u8], desc_len: usize) -> usize {
    NOTE_HDR_BYTES + round_up(name.len() + 1, NOTE_ALIGN) + round_up(desc_len, NOTE_ALIGN)
}

/// `v` advanced to the next multiple of `align`.
/// # C: O(1)
pub fn round_up(v: usize, align: usize) -> usize { (v + align - 1) / align * align }

fn pad_to(buf: &mut Vec<u8>, align: usize) { while buf.len() % align != 0 { buf.push(0); } }

/// Append one note: header, NUL-terminated name, descriptor, each padded.
/// # C: O(name + desc)
pub fn push_note(buf: &mut Vec<u8>, name: &[u8], ty: u32, desc: &[u8]) {
    let namesz = (name.len() + 1) as u32;
    buf.extend_from_slice(&namesz.to_le_bytes());
    buf.extend_from_slice(&(desc.len() as u32).to_le_bytes());
    buf.extend_from_slice(&ty.to_le_bytes());
    buf.extend_from_slice(name);
    buf.push(0);
    pad_to(buf, NOTE_ALIGN);
    buf.extend_from_slice(desc);
    pad_to(buf, NOTE_ALIGN);
}

fn put_i32(d: &mut [u8], off: usize, v: i32) { d[off..off + 4].copy_from_slice(&v.to_le_bytes()); }
fn put_u32(d: &mut [u8], off: usize, v: u32) { d[off..off + 4].copy_from_slice(&v.to_le_bytes()); }
fn put_u64(d: &mut [u8], off: usize, v: u64) { d[off..off + 8].copy_from_slice(&v.to_le_bytes()); }

fn put_timeval(d: &mut [u8], off: usize, tv: super::input::CoreTimeval) {
    d[off..off + 8].copy_from_slice(&tv.sec.to_le_bytes());
    d[off + 8..off + TIMEVAL_BYTES].copy_from_slice(&tv.usec.to_le_bytes());
}

/// Copy `src` into a fixed field, truncating so the terminator survives.
fn put_cstr(d: &mut [u8], off: usize, cap: usize, src: &[u8]) {
    let n = src.len().min(cap - 1);
    d[off..off + n].copy_from_slice(&src[..n]);
    d[off + n] = 0;
}

/// `elf_prstatus` for one thread: the killing signal, the thread's identity and
/// its register block.
/// # C: O(regs)
pub fn prstatus(arch: CoreArch, id: &CoreIdentity<'_>, t: &CoreThread<'_>) -> Vec<u8> {
    let mut d = alloc::vec![0u8; arch.prstatus_bytes()];
    put_i32(&mut d, PR_INFO_SIGNO_OFF, id.signo);
    d[PR_CURSIG_OFF..PR_CURSIG_OFF + 2].copy_from_slice(&(id.signo as i16).to_le_bytes());
    put_u64(&mut d, PR_SIGPEND_OFF, id.sigpend);
    put_u64(&mut d, PR_SIGHOLD_OFF, id.sighold);
    put_i32(&mut d, PR_PID_OFF,  t.tid);
    put_i32(&mut d, PR_PPID_OFF, id.ppid);
    put_i32(&mut d, PR_PGRP_OFF, id.pgrp);
    put_i32(&mut d, PR_SID_OFF,  id.sid);
    put_timeval(&mut d, PR_UTIME_OFF,  t.times.utime);
    put_timeval(&mut d, PR_STIME_OFF,  t.times.stime);
    put_timeval(&mut d, PR_CUTIME_OFF, id.times.cutime);
    put_timeval(&mut d, PR_CSTIME_OFF, id.times.cstime);
    d[PR_REG_OFF..PR_REG_OFF + t.regs.len()].copy_from_slice(t.regs);
    let fpvalid = if t.fpregs.is_some() { PR_FPVALID_TRUE } else { 0 };
    put_i32(&mut d, arch.pr_fpvalid_off(), fpvalid);
    d
}

/// `elf_prpsinfo`: the process identity a debugger prints before anything else.
/// # C: O(psargs)
pub fn prpsinfo(id: &CoreIdentity<'_>) -> Vec<u8> {
    let mut d = alloc::vec![0u8; PRPSINFO_BYTES];
    let state = id.state.index();
    d[PSINFO_STATE_OFF] = state;
    d[PSINFO_SNAME_OFF] = layout::sname_of(state);
    d[PSINFO_ZOMB_OFF]  = u8::from(layout::zombie_of(state));
    d[PSINFO_NICE_OFF]  = id.nice as u8;
    put_u64(&mut d, PSINFO_FLAG_OFF, id.flag);
    put_u32(&mut d, PSINFO_UID_OFF, id.uid);
    put_u32(&mut d, PSINFO_GID_OFF, id.gid);
    put_i32(&mut d, PSINFO_PID_OFF,  id.pid);
    put_i32(&mut d, PSINFO_PPID_OFF, id.ppid);
    put_i32(&mut d, PSINFO_PGRP_OFF, id.pgrp);
    put_i32(&mut d, PSINFO_SID_OFF,  id.sid);
    put_cstr(&mut d, PSINFO_FNAME_OFF, PSINFO_FNAME_BYTES, id.comm);
    // The argument block is NUL-separated in memory; the note renders it as one
    // readable line.
    let n = id.psargs.len().min(PSINFO_PSARGS_BYTES - 1);
    for i in 0..n {
        let c = id.psargs[i];
        d[PSINFO_PSARGS_OFF + i] = if c == 0 { b' ' } else { c };
    }
    d[PSINFO_PSARGS_OFF + n] = 0;
    d
}

/// `NT_FILE`: count and page size, then one triple per file-backed mapping, then
/// the mapping paths in the same order.
/// # C: O(segments + paths)
pub fn files(page_size: u64, segs: &[CoreSegment<'_>]) -> Option<Vec<u8>> {
    let count = segs.iter().filter(|s| s.file.is_some()).count();
    if count == 0 { return None }
    let names_off = (FILE_HDR_WORDS + FILE_ENTRY_WORDS * count) * FILE_WORD_BYTES;
    let mut d: Vec<u8> = Vec::with_capacity(names_off);
    d.extend_from_slice(&(count as u64).to_le_bytes());
    d.extend_from_slice(&page_size.to_le_bytes());
    for s in segs.iter() {
        let Some(f) = s.file else { continue };
        d.extend_from_slice(&s.start.to_le_bytes());
        d.extend_from_slice(&s.end.to_le_bytes());
        d.extend_from_slice(&f.pgoff_pages.to_le_bytes());
    }
    hal::kassert!(d.len() == names_off, "NT_FILE table length matches its header");
    for s in segs.iter() {
        let Some(f) = s.file else { continue };
        d.extend_from_slice(f.path);
        d.push(0);
    }
    Some(d)
}

/// Notes for one thread past the first: registers, then whatever extended state
/// the arch carries.
/// # C: O(notes)
pub fn push_thread_notes(buf: &mut Vec<u8>, arch: CoreArch, id: &CoreIdentity<'_>, t: &CoreThread<'_>) {
    push_note(buf, NOTE_NAME_CORE, NT_PRSTATUS, &prstatus(arch, id, t));
    push_fp_notes(buf, t);
}

/// The floating-point and extended-state notes of one thread.
/// # C: O(state)
pub fn push_fp_notes(buf: &mut Vec<u8>, t: &CoreThread<'_>) {
    if let Some(fp) = t.fpregs { push_note(buf, NOTE_NAME_CORE, NT_PRFPREG, fp) }
    if let Some(xs) = t.xstate { push_note(buf, NOTE_NAME_LINUX, NT_X86_XSTATE, xs) }
}

/// The process-wide notes, which follow the crashing thread's registers.
/// # C: O(auxv + segments)
pub fn push_process_notes(
    buf: &mut Vec<u8>, id: &CoreIdentity<'_>, auxv: &[u8], siginfo: Option<&[u8]>,
    page_size: u64, segs: &[CoreSegment<'_>],
) {
    push_note(buf, NOTE_NAME_CORE, NT_PRPSINFO, &prpsinfo(id));
    if let Some(si) = siginfo { push_note(buf, NOTE_NAME_CORE, NT_SIGINFO, si) }
    push_note(buf, NOTE_NAME_CORE, NT_AUXV, auxv);
    if let Some(f) = files(page_size, segs) { push_note(buf, NOTE_NAME_CORE, NT_FILE, &f) }
}
