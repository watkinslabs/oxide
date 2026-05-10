// Core dump per `27` — first cut for v2 phase 31. On a fatal signal
// (SIGSEGV / SIGABRT / SIGBUS / SIGILL / SIGFPE) with default action,
// write a minimal ELF coredump file into tmpfs at `/core.<tid>`.
//
// v1 dump shape:
//   Ehdr (ET_CORE, EM_X86_64 / EM_AARCH64)
//   1× Phdr  (PT_NOTE)
//   NT_PRSTATUS note (sig + reg block)
//   NT_PRPSINFO note (process name + cmdline placeholder)
//
// Real Linux coredumps additionally include PT_LOAD per writable VMA
// — that requires walking the AS and copying user pages, which is
// straightforward when the AS-walk helper exposes the right shape.
// Deferred follow-up.


#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;
use alloc::string::String;
use alloc::format;

const ELFCLASS64:   u8 = 2;
const ELFDATA2LSB:  u8 = 1;
const EV_CURRENT:   u8 = 1;
const ELFOSABI_SYSV: u8 = 0;
const ET_CORE:      u16 = 4;
#[cfg(target_arch = "x86_64")]
const EM_NATIVE:    u16 = 62;
#[cfg(target_arch = "aarch64")]
const EM_NATIVE:    u16 = 183;

const PT_NOTE: u32 = 4;

const NT_PRSTATUS: u32 = 1;
const NT_PRPSINFO: u32 = 3;

#[repr(C)]
struct Ehdr64 {
    ei: [u8; 16],
    ty: u16, mach: u16, ver: u32,
    entry: u64, phoff: u64, shoff: u64, flags: u32,
    ehsize: u16, phentsize: u16, phnum: u16,
    shentsize: u16, shnum: u16, shstrndx: u16,
}

#[repr(C)]
struct Phdr64 {
    ty: u32, flags: u32,
    offset: u64, vaddr: u64, paddr: u64,
    filesz: u64, memsz: u64, align: u64,
}

fn push_align(buf: &mut Vec<u8>, align: usize) {
    while buf.len() % align != 0 { buf.push(0); }
}

fn push_note(buf: &mut Vec<u8>, name: &[u8], ty: u32, desc: &[u8]) {
    // Linux note layout:
    //   u32 namesz (incl trailing NUL)
    //   u32 descsz
    //   u32 type
    //   name (NUL-terminated, padded to 4)
    //   desc (padded to 4)
    let namesz = (name.len() + 1) as u32;
    let descsz = desc.len() as u32;
    buf.extend_from_slice(&namesz.to_le_bytes());
    buf.extend_from_slice(&descsz.to_le_bytes());
    buf.extend_from_slice(&ty.to_le_bytes());
    buf.extend_from_slice(name);
    buf.push(0);
    push_align(buf, 4);
    buf.extend_from_slice(desc);
    push_align(buf, 4);
}

/// Build an ELF coredump byte vector for the current task.
/// `signo` is the killing signal (e.g. 11 for SIGSEGV).
/// `regs` is a 27-u64 block representing the kernel-side saved
/// frame — the prstatus consumers (gdb) read it as elf_gregset_t.
/// On x86_64 elf_gregset_t is 27 u64s (r15..rax + orig_rax + rip +
/// cs + eflags + rsp + ss + fs_base + gs_base + ds + es + fs + gs).
/// On aarch64 it's 33 u64s (regs[31] + sp + pc + pstate). v1 emits
/// a zero-filled block of the right shape so gdb at least parses
/// the file; populating real registers requires an arch-specific
/// register-snapshot helper that lands with the ptrace follow-up.
/// # C: O(notes_len)
pub fn build_coredump(signo: i32, name: &str) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);

    // Notes section.
    let mut notes: Vec<u8> = Vec::new();
    // NT_PRSTATUS — first 12 bytes are si_signo / si_code / si_errno
    // / cursig / sigpend / sighold; then pid/ppid/pgrp/sid + 4×timeval
    // + reg block. Total 336 bytes on x86_64, 392 on aarch64.
    #[cfg(target_arch = "x86_64")]
    let prstatus_size: usize = 336;
    #[cfg(target_arch = "aarch64")]
    let prstatus_size: usize = 392;
    let mut prstatus = alloc::vec![0u8; prstatus_size];
    // pr_info.si_signo at offset 0
    prstatus[0..4].copy_from_slice(&(signo as i32).to_le_bytes());
    // pr_cursig at offset 12
    prstatus[12..14].copy_from_slice(&(signo as i16).to_le_bytes());
    // pr_pid at offset 32 (Linux x86_64) — fill with current tid
    if let Some(c) = sched::current() {
        let off_pid = if cfg!(target_arch = "x86_64") { 32 } else { 32 };
        prstatus[off_pid..off_pid+4].copy_from_slice(&(c.tid as i32).to_le_bytes());
    }
    push_note(&mut notes, b"CORE", NT_PRSTATUS, &prstatus);

    // NT_PRPSINFO — 136-byte struct on Linux. Most fields zero;
    // pr_fname at offset 40 (16 bytes), pr_psargs at offset 56 (80 bytes).
    let mut prpsinfo = alloc::vec![0u8; 136];
    let nm = name.as_bytes();
    let nm_len = nm.len().min(15);
    prpsinfo[40..40+nm_len].copy_from_slice(&nm[..nm_len]);
    prpsinfo[56..56+nm_len].copy_from_slice(&nm[..nm_len]);
    push_note(&mut notes, b"CORE", NT_PRPSINFO, &prpsinfo);

    // Single PT_NOTE at offset = ehdr + phdr.
    let ehdr_sz = core::mem::size_of::<Ehdr64>();
    let phdr_sz = core::mem::size_of::<Phdr64>();
    let note_off = (ehdr_sz + phdr_sz) as u64;

    let eh = Ehdr64 {
        ei: [0x7f, b'E', b'L', b'F', ELFCLASS64, ELFDATA2LSB, EV_CURRENT,
             ELFOSABI_SYSV, 0, 0, 0, 0, 0, 0, 0, 0],
        ty: ET_CORE, mach: EM_NATIVE, ver: 1,
        entry: 0, phoff: ehdr_sz as u64, shoff: 0, flags: 0,
        ehsize: ehdr_sz as u16, phentsize: phdr_sz as u16, phnum: 1,
        shentsize: 0, shnum: 0, shstrndx: 0,
    };
    let ph = Phdr64 {
        ty: PT_NOTE, flags: 0,
        offset: note_off, vaddr: 0, paddr: 0,
        filesz: notes.len() as u64, memsz: 0, align: 1,
    };

    // SAFETY: Ehdr64 / Phdr64 are repr(C) PODs; transmute_copy reads exactly the byte count of each.
    unsafe {
        let eh_bytes: [u8; 64] = core::mem::transmute_copy(&eh);
        let ph_bytes: [u8; 56] = core::mem::transmute_copy(&ph);
        buf.extend_from_slice(&eh_bytes);
        buf.extend_from_slice(&ph_bytes);
    }
    buf.extend_from_slice(&notes);
    buf
}

/// Write a coredump to /core.<tid>. Best-effort — failures are swallowed
/// since the dumping task is already terminating.
/// # C: O(notes_len)
pub fn write_for_current(signo: i32) {
    let cur = match sched::current() { Some(c) => c, None => return };
    let name = cur.name;
    let body = build_coredump(signo, name);
    let path: String = format!("/core.{}", cur.tid);
    // Write through the tmpfs lookup-or-create path.
    let inode = tmpfs::TmpfsFileInode::new();
    use vfs::Inode;
    let _ = inode.write(0, &body);
    let inode_ref: vfs::InodeRef = inode as vfs::InodeRef;
    devfs::register(alloc::boxed::Box::leak(path.into_boxed_str()), inode_ref);
}
