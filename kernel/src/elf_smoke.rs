// ELF loader boot smoke per docs/31. Validates that
// `kernel::elf_load::load_static_blob` parses a hand-synthesised
// ELF64 and registers each PT_LOAD as a `VmaBacking::KernelBytes`
// VMA in the global user `AddressSpace`.
//
// Drop-to-ring3 of the loaded image lives in a follow-up PR
// (P2-16b) which factors `userspace_smoke`'s iretq frame builder
// into a reusable primitive. Today's smoke proves the parse +
// VMA registration path lights up cleanly under the boot trace.

#![cfg(target_os = "oxide-kernel")]
#![cfg(target_arch = "x86_64")]

use crate::elf_load::load_static_blob;

/// Build a tiny ELF64 image at compile time.
///   [0..64)    ehdr
///   [64..120)  PT_LOAD phdr
///   [120..128) pad
///   [128..161) code (33 B — write+exit+ud2)
///   [161..164) "el\n"
const fn build_elf() -> [u8; 164] {
    let mut b = [0u8; 164];
    // e_ident
    b[0]=0x7f; b[1]=b'E'; b[2]=b'L'; b[3]=b'F';
    b[4]=2;   // ELFCLASS64
    b[5]=1;   // ELFDATA2LSB
    b[6]=1;   // EV_CURRENT
    // e_type=ET_EXEC, e_machine=EM_X86_64, e_version=1
    b[16]=2; b[18]=62; b[20]=1;
    // e_entry = 0x400080
    let entry: u64 = 0x400080;
    let eb = entry.to_le_bytes();
    let mut i = 0; while i < 8 { b[24 + i] = eb[i]; i += 1; }
    // e_phoff = 64
    b[32]=64;
    // e_ehsize=64, e_phentsize=56, e_phnum=1
    b[52]=64; b[54]=56; b[56]=1;

    // PT_LOAD phdr at offset 64
    let p = 64;
    b[p+0]=1;     // p_type = PT_LOAD
    b[p+4]=5;     // p_flags = R|X
    // p_offset = 0
    // p_vaddr = 0x400000
    let v: u64 = 0x400000;
    let vb = v.to_le_bytes();
    i = 0; while i < 8 { b[p+16+i] = vb[i]; i += 1; }
    // p_paddr = same
    i = 0; while i < 8 { b[p+24+i] = vb[i]; i += 1; }
    // p_filesz = 164
    let fs: u64 = 164;
    let fb = fs.to_le_bytes();
    i = 0; while i < 8 { b[p+32+i] = fb[i]; i += 1; }
    // p_memsz = 164
    i = 0; while i < 8 { b[p+40+i] = fb[i]; i += 1; }
    // p_align = 0x1000
    let al: u64 = 0x1000;
    let ab = al.to_le_bytes();
    i = 0; while i < 8 { b[p+48+i] = ab[i]; i += 1; }

    // Code at file offset 128 (= vaddr 0x400080):
    //   mov $1, %eax              ; sys_write
    //   mov $1, %edi              ; fd=1
    //   mov $0x4000A1, %esi       ; buf
    //   mov $3, %edx              ; len
    //   syscall
    //   mov $60, %eax             ; sys_exit
    //   xor %edi, %edi
    //   syscall
    //   ud2                        ; landmark
    let c = 128;
    b[c+0]=0xB8; b[c+1]=0x01;
    b[c+5]=0xBF; b[c+6]=0x01;
    b[c+10]=0xBE; b[c+11]=0xA1; b[c+12]=0x00; b[c+13]=0x40; b[c+14]=0x00;
    b[c+15]=0xBA; b[c+16]=0x03;
    b[c+20]=0x0F; b[c+21]=0x05;
    b[c+22]=0xB8; b[c+23]=0x3C;
    b[c+27]=0x31; b[c+28]=0xFF;
    b[c+29]=0x0F; b[c+30]=0x05;
    b[c+31]=0x0F; b[c+32]=0x0B;
    // Buffer "el\n" at file offset 161 = vaddr 0x4000A1
    b[161]=b'e'; b[162]=b'l'; b[163]=b'\n';
    b
}

const ELF_BLOB_BYTES: [u8; 164] = build_elf();
const ELF_BLOB: &'static [u8] = &ELF_BLOB_BYTES;

/// Parse + load the synthesised ELF into the global user AS.
/// Logs `elf-smoke: load ok entry=...` on success and the error
/// code on failure. Idempotent across multiple boots in the same
/// build (the AS is populated with overlapping MAP_FIXED, which
/// the loader handles via clear-then-place per `11§6`).
///
/// # SAFETY: caller is the boot path; user_as::init has run; PMM
/// + MmuOps state initialised; single-CPU pre-init.
/// # C: O(phdrs) parse + O(phdrs) mmap
/// # Ctx: pre-init, IRQ-off, single-CPU
pub fn run() {
    let r = crate::user_as::with(|as_| load_static_blob(ELF_BLOB, as_));
    match r {
        Some(Ok(img)) => {
            debug_irq! {
                klog::write_raw(b"[INFO]  elf-smoke: load ok entry=");
                klog::write_hex_u64(img.entry.as_u64());
                klog::write_raw(b" brk=");
                klog::write_hex_u64(img.brk.as_u64());
                klog::write_raw(b"\n");
            }
            let _ = img;
        }
        Some(Err(e)) => {
            debug_irq! {
                klog::write_raw(b"[FAULT] elf-smoke: load failed err=");
                klog::write_dec_u64(e as u64);
                klog::write_raw(b"\n");
            }
            let _ = e;
        }
        None => {
            debug_irq! {
                klog::kerror!("elf-smoke: user_as not initialised");
            }
        }
    }
}
