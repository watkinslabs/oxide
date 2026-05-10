// ELF execution smoke per docs/31§4. Parses a hand-synthesised
// ELF64, loads it into the global user `AddressSpace` via
// `VmaBacking::KernelBytes` (P2-17), registers an anonymous stack
// VMA, and drops to ring 3 at `e_entry`. Demand-paging copies
// the ELF bytes into freshly-allocated user pages on first
// access — no manual `MmuOps::map` calls.
//
// The user blob does `write(1, "el\\n", 3); exit(0); ud2`; the
// `#UD` landmark at the end is caught by the smoke handler so we
// have a deterministic halt point matching the prior
// `userspace_smoke` shape.

#![cfg(target_os = "oxide-kernel")]
#![cfg(target_arch = "x86_64")]

use elf_load::load_static_blob;

/// Build an init-like fork+wait4+execve loop ELF64 at compile
/// time. Three iterations: parent forks → child execs YO
/// ("yo\\n"); parent waits → forks → child execs HI ("hi\\n");
/// parent waits → forks → child execs ECHO (read 1 byte from
/// fd 0, write it back to fd 1); parent waits → exits. ECHO is
/// fed by `tty::inject_for_smoke(b"A")` at boot so the smoke
/// runs non-interactively — boot trace shows yo / hi / A.
///
/// Layout:
///   [0..64)     ehdr
///   [64..120)   PT_LOAD phdr
///   [120..128)  pad
///   [128..368)  code (240 B): 4 iterations × 60 B
///   [368..379)  final exit (11 B)
///   [379..383)  'y','h','e','c' at vaddrs 0x4001/7B/7C/7D/7E
const fn build_elf() -> [u8; 383] {
    let mut b = [0u8; 383];
    b[0]=0x7f; b[1]=b'E'; b[2]=b'L'; b[3]=b'F';
    b[4]=2; b[5]=1; b[6]=1;
    b[16]=2; b[18]=62; b[20]=1;
    let entry: u64 = 0x400080;
    let eb = entry.to_le_bytes();
    let mut i = 0; while i < 8 { b[24 + i] = eb[i]; i += 1; }
    b[32]=64;
    b[52]=64; b[54]=56; b[56]=1;

    let p = 64;
    b[p+0]=1; b[p+4]=5;                  // PT_LOAD R|X
    let v: u64 = 0x400000;
    let vb = v.to_le_bytes();
    i = 0; while i < 8 { b[p+16+i] = vb[i]; i += 1; }
    i = 0; while i < 8 { b[p+24+i] = vb[i]; i += 1; }
    let fs: u64 = 383;
    let fb = fs.to_le_bytes();
    i = 0; while i < 8 { b[p+32+i] = fb[i]; i += 1; }
    i = 0; while i < 8 { b[p+40+i] = fb[i]; i += 1; }
    let al: u64 = 0x1000;
    let ab = al.to_le_bytes();
    i = 0; while i < 8 { b[p+48+i] = ab[i]; i += 1; }

    // 4 iterations × 60 B each. Selectors at vaddrs 0x40017B..7E:
    //   iter 1: 'y' (sel_lo = 0x7B)
    //   iter 2: 'h' (sel_lo = 0x7C)
    //   iter 3: 'e' (sel_lo = 0x7D) — ECHO
    //   iter 4: 'c' (sel_lo = 0x7E) — CAT (open /proc/version + write)
    let c = 128;
    iter_block(&mut b, c,        0x7B);
    iter_block(&mut b, c + 60,   0x7C);
    iter_block(&mut b, c + 120,  0x7D);
    iter_block(&mut b, c + 180,  0x7E);
    // Final exit at offset 240.
    let e = c + 240;
    b[e+0]=0xB8; b[e+1]=0x3C;             // mov $60, %eax
    b[e+5]=0x31; b[e+6]=0xFF;             // xor %edi, %edi
    b[e+7]=0x0F; b[e+8]=0x05;             // syscall (exit)
    b[e+9]=0x0F; b[e+10]=0x0B;            // ud2
    // Selectors at file offsets 379..382 → vaddrs 0x40017B..7E.
    b[379]=b'y';
    b[380]=b'h';
    b[381]=b'e';
    b[382]=b'c';
    b
}

/// Emit one fork+jne+child(execve `sel_lo`)+failsafe+wait4 block
/// at file-offset `off` within `b`. `sel_lo` is the low byte of
/// the selector VA (0x400000 | (sel_lo as u32)) — the selector
/// itself sits at file offset == vaddr & 0xfff. Block size = 60 B.
const fn iter_block(b: &mut [u8; 383], off: usize, sel_lo: u8) {
    // [0x00] mov $57, %eax            ; sys_fork
    b[off+0]=0xB8; b[off+1]=0x39;
    // [0x05] syscall
    b[off+5]=0x0F; b[off+6]=0x05;
    // [0x07] test %eax, %eax
    b[off+7]=0x85; b[off+8]=0xC0;
    // [0x09] jne +0x1E → 0x29 (wait4)  ; parent path
    b[off+9]=0x75; b[off+10]=0x1E;
    // CHILD PATH (file offset off+0x0B..off+0x29):
    // [0x0B] mov $sel_va, %edi
    b[off+11]=0xBF; b[off+12]=sel_lo; b[off+13]=0x01; b[off+14]=0x40; b[off+15]=0x00;
    // [0x10] mov $59, %eax            ; sys_execve
    b[off+16]=0xB8; b[off+17]=0x3B;
    // [0x15] xor %esi, %esi           ; argv=NULL
    b[off+21]=0x31; b[off+22]=0xF6;
    // [0x17] xor %edx, %edx           ; envp=NULL
    b[off+23]=0x31; b[off+24]=0xD2;
    // [0x19] syscall (execve)
    b[off+25]=0x0F; b[off+26]=0x05;
    // [0x1B] mov $60, %eax            ; failsafe exit
    b[off+27]=0xB8; b[off+28]=0x3C;
    // [0x20] mov $1, %edi
    b[off+32]=0xBF; b[off+33]=0x01;
    // [0x25] syscall (exit)
    b[off+37]=0x0F; b[off+38]=0x05;
    // [0x27] ud2
    b[off+39]=0x0F; b[off+40]=0x0B;
    // PARENT WAIT4 (file offset off+0x29..off+0x3C):
    // [0x29] mov $61, %eax            ; sys_wait4
    b[off+41]=0xB8; b[off+42]=0x3D;
    // [0x2E] mov $-1, %edi
    b[off+46]=0xBF; b[off+47]=0xFF; b[off+48]=0xFF; b[off+49]=0xFF; b[off+50]=0xFF;
    // [0x33] xor %esi, %esi
    b[off+51]=0x31; b[off+52]=0xF6;
    // [0x35] xor %edx, %edx
    b[off+53]=0x31; b[off+54]=0xD2;
    // [0x37] xor %r10d, %r10d
    b[off+55]=0x45; b[off+56]=0x31; b[off+57]=0xD2;
    // [0x3A] syscall (wait4)
    b[off+58]=0x0F; b[off+59]=0x05;
}

const ELF_BLOB_BYTES: [u8; 383] = build_elf();
const ELF_BLOB: &'static [u8] = &ELF_BLOB_BYTES;

/// Build a "writes 2-char message + exit" ELF64. `c0`/`c1` are
/// the two output chars; the program writes `[c0, c1, '\n']` then
/// exits cleanly.
const fn build_named_blob(c0: u8, c1: u8) -> [u8; 164] {
    let mut b = [0u8; 164];
    b[0]=0x7f; b[1]=b'E'; b[2]=b'L'; b[3]=b'F';
    b[4]=2; b[5]=1; b[6]=1;
    b[16]=2; b[18]=62; b[20]=1;
    let entry: u64 = 0x400080;
    let eb = entry.to_le_bytes();
    let mut i = 0; while i < 8 { b[24 + i] = eb[i]; i += 1; }
    b[32]=64;
    b[52]=64; b[54]=56; b[56]=1;

    let p = 64;
    b[p+0]=1; b[p+4]=5;                          // PT_LOAD R|X
    let v: u64 = 0x400000;
    let vb = v.to_le_bytes();
    i = 0; while i < 8 { b[p+16+i] = vb[i]; i += 1; }
    i = 0; while i < 8 { b[p+24+i] = vb[i]; i += 1; }
    let fs: u64 = 164;
    let fb = fs.to_le_bytes();
    i = 0; while i < 8 { b[p+32+i] = fb[i]; i += 1; }
    i = 0; while i < 8 { b[p+40+i] = fb[i]; i += 1; }
    let al: u64 = 0x1000;
    let ab = al.to_le_bytes();
    i = 0; while i < 8 { b[p+48+i] = ab[i]; i += 1; }

    // Code at file offset 128 (vaddr 0x400080) — write 3 bytes
    // (c0, c1, '\n') + exit. Buffer at file offset 161 = vaddr
    // 0x4000A1.
    let c = 128;
    b[c+0]=0xB8; b[c+1]=0x01;                                  // mov $1, %eax
    b[c+5]=0xBF; b[c+6]=0x01;                                  // mov $1, %edi
    b[c+10]=0xBE; b[c+11]=0xA1; b[c+12]=0x00; b[c+13]=0x40; b[c+14]=0x00; // mov $0x4000A1, %esi
    b[c+15]=0xBA; b[c+16]=0x03;                                // mov $3, %edx
    b[c+20]=0x0F; b[c+21]=0x05;                                // syscall
    b[c+22]=0xB8; b[c+23]=0x3C;                                // mov $60, %eax
    b[c+27]=0x31; b[c+28]=0xFF;                                // xor %edi, %edi
    b[c+29]=0x0F; b[c+30]=0x05;                                // syscall
    b[c+31]=0x0F; b[c+32]=0x0B;                                // ud2
    b[161]=c0; b[162]=c1; b[163]=b'\n';
    b
}

const HI_BLOB_BYTES: [u8; 164] = build_named_blob(b'h', b'i');
const YO_BLOB_BYTES: [u8; 164] = build_named_blob(b'y', b'o');
/// Programs the table-driven `sys_execve` can load by name (P2-21b).
pub const HI_BLOB: &'static [u8] = &HI_BLOB_BYTES;
pub const YO_BLOB: &'static [u8] = &YO_BLOB_BYTES;

/// Build an ECHO ELF: read 1 byte from fd=0, write to fd=1, exit.
/// v1 demonstrates the fd_table → ConsoleInode → tty ringbuffer
/// end-to-end (P3-02). The 1-byte read buffer lives at the heap's
/// initial brk (vaddr 0x401000) — the loader pre-registers an
/// Anonymous R|W VMA covering the heap so the page demand-faults
/// to a fresh zero frame on first write. Keeps PT_LOAD R|X (no
/// W^X violation per docs/31§2 invariant 3).
const fn build_echo_blob() -> [u8; 173] {
    let mut b = [0u8; 173];
    b[0]=0x7f; b[1]=b'E'; b[2]=b'L'; b[3]=b'F';
    b[4]=2; b[5]=1; b[6]=1;
    b[16]=2; b[18]=62; b[20]=1;
    let entry: u64 = 0x400080;
    let eb = entry.to_le_bytes();
    let mut i = 0; while i < 8 { b[24 + i] = eb[i]; i += 1; }
    b[32]=64;
    b[52]=64; b[54]=56; b[56]=1;

    let p = 64;
    b[p+0]=1; b[p+4]=5;                          // PT_LOAD R|X
    let v: u64 = 0x400000;
    let vb = v.to_le_bytes();
    i = 0; while i < 8 { b[p+16+i] = vb[i]; i += 1; }
    i = 0; while i < 8 { b[p+24+i] = vb[i]; i += 1; }
    let fs: u64 = 173;
    let fb = fs.to_le_bytes();
    i = 0; while i < 8 { b[p+32+i] = fb[i]; i += 1; }
    i = 0; while i < 8 { b[p+40+i] = fb[i]; i += 1; }
    let al: u64 = 0x1000;
    let ab = al.to_le_bytes();
    i = 0; while i < 8 { b[p+48+i] = ab[i]; i += 1; }

    // Code at file offset 128 (vaddr 0x400080):
    //   mov $0, %eax            ; sys_read (= 0)
    //   mov $0, %edi            ; fd=0
    //   mov $0x401000, %esi     ; buf in heap region (R|W via P2-32)
    //   mov $1, %edx            ; len=1
    //   syscall
    //   mov $1, %eax            ; sys_write (= 1)
    //   mov $1, %edi            ; fd=1
    //   ; esi/edx still hold buf/len from the read
    //   syscall
    //   mov $60, %eax           ; sys_exit
    //   xor %edi, %edi
    //   syscall
    //   ud2
    let c = 128;
    b[c+0]=0xB8;                                   // mov $0, %eax (zero default)
    b[c+5]=0xBF;                                   // mov $0, %edi
    b[c+10]=0xBE; b[c+11]=0x00; b[c+12]=0x10; b[c+13]=0x40; b[c+14]=0x00;  // 0x401000
    b[c+15]=0xBA; b[c+16]=0x01;                    // mov $1, %edx
    b[c+20]=0x0F; b[c+21]=0x05;                    // syscall (read)
    b[c+22]=0xB8; b[c+23]=0x01;                    // mov $1, %eax
    b[c+27]=0xBF; b[c+28]=0x01;                    // mov $1, %edi
    b[c+32]=0x0F; b[c+33]=0x05;                    // syscall (write)
    b[c+34]=0xB8; b[c+35]=0x3C;                    // mov $60, %eax
    b[c+39]=0x31; b[c+40]=0xFF;                    // xor %edi, %edi
    b[c+41]=0x0F; b[c+42]=0x05;                    // syscall (exit)
    b[c+43]=0x0F; b[c+44]=0x0B;                    // ud2
    b
}

const ECHO_BLOB_BYTES: [u8; 173] = build_echo_blob();
/// "echo" program: read 1 byte from fd=0, write it to fd=1,
/// exit. Selector: 'e'.
pub const ECHO_BLOB: &'static [u8] = &ECHO_BLOB_BYTES;

/// Build a CAT ELF: open("/proc/version", O_RDONLY), read 64
/// bytes into the heap, write them to fd=1, close, exit. Validates
/// sys_open + procfs + multi-byte sys_read + sys_write + sys_close
/// end-to-end from a real ring-3 binary. Path string sits at file
/// offset 220 (vaddr 0x4000DC).
const fn build_cat_blob() -> [u8; 256] {
    let mut b = [0u8; 256];
    b[0]=0x7f; b[1]=b'E'; b[2]=b'L'; b[3]=b'F';
    b[4]=2; b[5]=1; b[6]=1;
    b[16]=2; b[18]=62; b[20]=1;
    let entry: u64 = 0x400080;
    let eb = entry.to_le_bytes();
    let mut i = 0; while i < 8 { b[24 + i] = eb[i]; i += 1; }
    b[32]=64;
    b[52]=64; b[54]=56; b[56]=1;

    let p = 64;
    b[p+0]=1; b[p+4]=5;                          // PT_LOAD R|X
    let v: u64 = 0x400000;
    let vb = v.to_le_bytes();
    i = 0; while i < 8 { b[p+16+i] = vb[i]; i += 1; }
    i = 0; while i < 8 { b[p+24+i] = vb[i]; i += 1; }
    let fs: u64 = 256;
    let fb = fs.to_le_bytes();
    i = 0; while i < 8 { b[p+32+i] = fb[i]; i += 1; }
    i = 0; while i < 8 { b[p+40+i] = fb[i]; i += 1; }
    let al: u64 = 0x1000;
    let ab = al.to_le_bytes();
    i = 0; while i < 8 { b[p+48+i] = ab[i]; i += 1; }

    // Code at file offset 128 (vaddr 0x400080).
    let c = 128;
    // open("/proc/version", O_RDONLY, 0)
    b[c+0]=0xB8; b[c+1]=0x02;                                   // mov $2, %eax
    b[c+5]=0xBF; b[c+6]=0xDC; b[c+7]=0x00; b[c+8]=0x40; b[c+9]=0x00; // mov $0x4000DC, %edi
    b[c+10]=0x31; b[c+11]=0xF6;                                 // xor %esi, %esi
    b[c+12]=0x31; b[c+13]=0xD2;                                 // xor %edx, %edx
    b[c+14]=0x0F; b[c+15]=0x05;                                 // syscall (open)
    // mov %eax, %ebx
    b[c+16]=0x89; b[c+17]=0xC3;
    // read(fd, 0x401000, 64)
    b[c+18]=0x31; b[c+19]=0xC0;                                 // xor %eax, %eax (read=0)
    b[c+20]=0x89; b[c+21]=0xDF;                                 // mov %ebx, %edi
    b[c+22]=0xBE; b[c+23]=0x00; b[c+24]=0x10; b[c+25]=0x40; b[c+26]=0x00; // mov $0x401000, %esi
    b[c+27]=0xBA; b[c+28]=0x40; b[c+29]=0x00; b[c+30]=0x00; b[c+31]=0x00; // mov $64, %edx
    b[c+32]=0x0F; b[c+33]=0x05;                                 // syscall (read)
    // write(1, 0x401000, len)  — len from rax above goes to rdx
    b[c+34]=0x89; b[c+35]=0xC2;                                 // mov %eax, %edx
    b[c+36]=0xB8; b[c+37]=0x01;                                 // mov $1, %eax
    b[c+41]=0xBF; b[c+42]=0x01;                                 // mov $1, %edi
    b[c+46]=0xBE; b[c+47]=0x00; b[c+48]=0x10; b[c+49]=0x40; b[c+50]=0x00; // mov $0x401000, %esi
    b[c+51]=0x0F; b[c+52]=0x05;                                 // syscall (write)
    // close(fd)
    b[c+53]=0xB8; b[c+54]=0x03;                                 // mov $3, %eax
    b[c+58]=0x89; b[c+59]=0xDF;                                 // mov %ebx, %edi
    b[c+60]=0x0F; b[c+61]=0x05;                                 // syscall (close)
    // exit(0)
    b[c+62]=0xB8; b[c+63]=0x3C;                                 // mov $60, %eax
    b[c+67]=0x31; b[c+68]=0xFF;                                 // xor %edi, %edi
    b[c+69]=0x0F; b[c+70]=0x05;                                 // syscall (exit)
    b[c+71]=0x0F; b[c+72]=0x0B;                                 // ud2

    // Path "/proc/version\0" at file offset 220 (vaddr 0x4000DC).
    let path = b"/proc/version\0";
    let mut k = 0;
    while k < path.len() { b[220 + k] = path[k]; k += 1; }
    b
}

const CAT_BLOB_BYTES: [u8; 256] = build_cat_blob();
/// "cat" program: opens /proc/version, reads 64 bytes, writes to
/// fd=1, exits. Selector: 'c'.
pub const CAT_BLOB: &'static [u8] = &CAT_BLOB_BYTES;

/// Look up the kernel-static ELF for a given path's first byte
/// (v1 selector — full path lookup waits on VFS per docs/16).
/// Returns the matching blob or `None` for unknown paths.
/// # C: O(1)
pub fn lookup_blob(selector: u8) -> Option<&'static [u8]> {
    match selector {
        b'h' => Some(HI_BLOB),
        b'y' => Some(YO_BLOB),
        b'e' => Some(ECHO_BLOB),
        b'c' => Some(CAT_BLOB),
        _    => None,
    }
}

/// Path-string lookup for `sys_execve`. Tries the real ext4
/// rootfs first (P6-08); falls back to the const-blob table for
/// the hand-synthesized orchestrator binaries that aren't on
/// disk. Returns `None` if no matching binary anywhere.
///
/// ext4 reads return owned `Vec<u8>` which we leak so the
/// caller gets `&'static [u8]` (matching the const-blob path).
/// One leak per execve is fine for v1 — Phase 7a page-cache
/// integration replaces this with cached pages.
/// # C: O(path lookup) ext4 / O(1) const-table fallback
pub fn lookup_blob_by_path(path: &[u8]) -> Option<&'static [u8]> {
    #[cfg(target_os = "oxide-kernel")]
    {
        if let Some(bytes) = ext4::rootfs::read_file(path) {
            // Leak to 'static: kernel-lifetime stable storage.
            let leaked: &'static [u8] = alloc::boxed::Box::leak(bytes.into_boxed_slice());
            return Some(leaked);
        }
    }
    match path {
        b"/init" | b"/sbin/init"            => Some(ELF_BLOB_PUB),
        b"/bin/yo" | b"/usr/bin/yo"         => Some(YO_BLOB),
        b"/bin/hi" | b"/usr/bin/hi"         => Some(HI_BLOB),
        b"/bin/echo" | b"/usr/bin/echo"     => Some(ECHO_BLOB),
        b"/bin/cat"  | b"/usr/bin/cat"      => Some(CAT_BLOB),
        b"/bin/hello" | b"/usr/bin/hello"   => Some(HELLO_BLOB),
        _ => None,
    }
}

/// Re-export ELF_BLOB for the path-string lookup. Internal const
/// can't be `pub` directly without touching the existing access
/// patterns; this wrapper exposes it under a dedicated name.
pub const ELF_BLOB_PUB: &'static [u8] = ELF_BLOB;

/// musl static-PIE helloworld blob (P3-59 / M1). Built with
/// `musl-gcc -static-pie -fPIE -O2`. First non-hand-rolled binary
/// the kernel executes — validates the ELF loader against a real
/// toolchain output (DT_RELA self-relocs, .text/.rodata/.data
/// segments, real auxv consumption).
pub const HELLO_BLOB: &'static [u8] = include_bytes!("../blobs/hello.elf");

/// P3-66 sa_handler dispatch smoke. Hand-rolled static-PIE ELF
/// that registers a SIGUSR1 handler, raises SIGUSR1 to itself
/// via sys_kill, and verifies the handler ran + rt_sigreturn
/// restored execution. Boot trace shows "before h after" if the
/// signal-dispatch chain works end-to-end.
pub const SIGTEST_BLOB: &'static [u8] = include_bytes!("../blobs/sigtest.elf");

/// P3-77 tmpfs end-to-end smoke. Hand-rolled static-PIE ELF that
/// open(O_CREAT)+write+close /tmp/x then open(RD)+read+write(1)
/// to validate the tmpfs path through `sys_open` + `fs::tmpfs::lookup_or_create`.
pub const TMPFSTEST_BLOB: &'static [u8] = include_bytes!("../blobs/tmpfstest.elf");

/// Boot-time smoke: kassert each registered path resolves to a
/// non-empty ELF blob with the expected magic bytes.
/// # SAFETY: caller is the boot path; pre-init.
/// # C: O(N_paths)
pub fn lookup_smoke() {
    use hal::kassert;
    let paths: &[&[u8]] = &[
        b"/init", b"/sbin/init",
        b"/bin/yo", b"/bin/hi", b"/bin/echo", b"/bin/cat",
        b"/usr/bin/yo", b"/usr/bin/hi", b"/usr/bin/echo", b"/usr/bin/cat",
    ];
    for &p in paths {
        let b = lookup_blob_by_path(p).expect("lookup_blob_by_path");
        kassert!(b.len() >= 4, "blob too short");
        kassert!(b[0] == 0x7F && b[1] == b'E' && b[2] == b'L' && b[3] == b'F',
                 "blob ELF magic");
    }
    let miss = lookup_blob_by_path(b"/nonexistent");
    kassert!(miss.is_none(), "negative lookup should miss");
    debug_boot! { klog::write_raw(b"[INFO]  exec-path-smoke: ok\n"); }
}

/// Default blob for the `path = NULL` legacy path (P2-21 v0).
/// Retained so older test paths keep working.
pub const EXEC_BLOB: &'static [u8] = HI_BLOB;

/// User stack length for boot-spawned user blobs. 64 KiB matches
/// the execve path; the prior 4 KiB underflowed in the first wide
/// musl init frame and the prior VA (0x501_000) collided with
/// busybox's 1 MiB .text segment, chopping a hole in code while
/// giving init no room. Place near the top of user-half VA so we
/// stay disjoint from any reasonable ELF text.
pub const EXEC_USER_STACK_LEN: u64 = 0x10000;
pub const EXEC_USER_STACK_VA:  u64 = hal::USER_VA_END - 0x20000;
pub const EXEC_USER_STACK_TOP: u64 = EXEC_USER_STACK_VA + EXEC_USER_STACK_LEN;

const USER_STACK_LEN: u64 = EXEC_USER_STACK_LEN;
const USER_STACK_VA:  u64 = EXEC_USER_STACK_VA;
const USER_STACK_TOP: u64 = EXEC_USER_STACK_TOP;

/// ud2 landmark addresses for the init-like ELF. Each iteration
/// has a child failsafe ud2 at `entry+iter_off+0x27`; the final
/// exit's ud2 is at `entry+0x84`. Named blobs' ud2 lives at
/// `entry+0x1F`.
const USER_RIP_UD2_ITER1_FS: u64 = 0x400080 + 0x27;
const USER_RIP_UD2_ITER2_FS: u64 = 0x400080 + 60 + 0x27;
const USER_RIP_UD2_ITER3_FS: u64 = 0x400080 + 2*60 + 0x27;
const USER_RIP_UD2_ITER4_FS: u64 = 0x400080 + 3*60 + 0x27;
const USER_RIP_UD2_FINAL:    u64 = 0x400080 + 4*60 + 9;
const USER_RIP_UD2_EXEC:     u64 = 0x400080 + 0x1F;
const USER_RIP_UD2_ECHO:     u64 = 0x400080 + 0x2B;

/// `#UD` landmark handler. Chains to user_as for legitimate
/// demand-page faults; on the deliberate ud2 from sys_exit's
/// sysretq landing, logs the success line.
fn elf_smoke_fault_handler(vec: u64, err: u64, rip: u64, cr2: u64) -> bool {
    if crate::user_as::user_fault_handler(vec, err, rip, cr2) {
        return true;
    }
    if vec == 6 && (rip == USER_RIP_UD2_ITER1_FS
                    || rip == USER_RIP_UD2_ITER2_FS
                    || rip == USER_RIP_UD2_ITER3_FS
                    || rip == USER_RIP_UD2_ITER4_FS
                    || rip == USER_RIP_UD2_FINAL
                    || rip == USER_RIP_UD2_EXEC
                    || rip == USER_RIP_UD2_ECHO) {
        debug_irq! {
            klog::write_raw(b"[INFO]  elf-smoke: ok ring3 #UD rip=");
            klog::write_hex_u64(rip);
            klog::write_raw(b"\n");
        }
    }
    false
}

/// Spawn the loaded ELF as a real user `Task` on the runqueue
/// and `schedule()` into it. The task carries
/// `Arc<AddressSpace>`, so future fork/execve can reach it via
/// `sched::current().mm`. Diverges via the deliberate ud2
/// landmark after sys_exit's sysretq → smoke fault handler.
///
/// Foundation for fork/execve: introduces a real "current user
/// task" backed by `mm`, replacing the prior `drop_to_ring3`
/// flow that ran user code without any Task wrapper.
///
/// Installs a fresh runqueue if one isn't already present.
///
/// # SAFETY: caller is the boot path; user_as::init has run; PMM
/// + GDT + TSS + IDT + syscall MSRs initialised; single-CPU;
/// IRQs masked.
/// # C: O(phdrs) parse + O(log N) enqueue
/// # Ctx: pre-init, IRQ-off, single-CPU; diverges
pub unsafe fn run_as_task(_hhdm_offset: u64) -> ! {
    if !sched::live::runqueue_active() {
        // SAFETY: boot path; allocator up; no concurrent runqueue users.
        unsafe { sched::live::install_default_runqueue(); }
    }
    use vmm::{VmaBacking, VmaFlags, VmaProt};
    use hal::UserVirtAddr;

    // Install the fault handler BEFORE load: PIE relocation
    // application writes through user mappings that may need
    // demand-fault resolution (kernel-mode #PF on user VA).
    // SAFETY: handler fn is 'static; pre-init single-CPU swap.
    unsafe { hal_x86_64::install_fault_handler(elf_smoke_fault_handler); }

    let img = match crate::user_as::with(|as_| {
        let img = load_static_blob(ELF_BLOB, as_)?;
        // Stack VMA — anonymous, demand-paged on first push.
        let stack_hint = UserVirtAddr::new(USER_STACK_VA)
            .ok_or(elf_load::LoadError::Einval)?;
        as_.mmap(
            Some(stack_hint), USER_STACK_LEN as usize,
            VmaProt::READ | VmaProt::WRITE,
            VmaFlags::PRIVATE | VmaFlags::ANONYMOUS,
            VmaBacking::Anonymous,
            true,
        ).map_err(|_| elf_load::LoadError::Enomem)?;
        Ok::<_, elf_load::LoadError>(img)
    }) {
        Some(Ok(i))  => i,
        Some(Err(e)) => {
            debug_irq! {
                klog::write_raw(b"[FAULT] elf-smoke: setup failed err=");
                klog::write_dec_u64(e as u64);
                klog::write_raw(b"\n");
            }
            let _ = e;
            halt_forever();
        }
        None => {
            debug_irq! { klog::kerror!("elf-smoke: user_as not initialised"); }
            halt_forever();
        }
    };

    debug_irq! {
        klog::write_raw(b"[INFO]  elf-smoke: load ok entry=");
        klog::write_hex_u64(img.entry.as_u64());
        klog::write_raw(b" brk=");
        klog::write_hex_u64(img.brk.as_u64());
        klog::write_raw(b"\n");
    }

    // Build the SysV initial stack (argc/argv/envp/auxv) for the
    // user task per docs/31§4. The musl `_start` entry expects to
    // find argc at SP; without this it reads garbage and faults.
    let random16 = {
        use hal::TimerOps;
        let ns = hal_x86_64::X86TimerOps::monotonic_ns().0;
        let mut r = [0u8; 16];
        for i in 0..16 { r[i] = (ns >> ((i % 8) * 8)) as u8 ^ (i as u8 * 0x9b); }
        r
    };
    // SAFETY: global user AS is the active CR3 per init; build_user_stack writes via that mapping; user_fault_handler resolves the demand-faulted stack page.
    let new_sp = unsafe {
        elf_load::stack::build_user_stack(
            USER_STACK_TOP,
            &[b"/init"], &[],
            &img,
            &random16,
            b"/init",
        )
    }.unwrap_or(USER_STACK_TOP);

    let mm = match crate::user_as::clone_global_arc() {
        Some(a) => a,
        None    => { debug_irq! { klog::kerror!("elf-smoke: AS clone failed"); } halt_forever(); }
    };

    // Spawn the user task on the runqueue.
    // SAFETY: runqueue installed by kernel_main earlier; mm matches active CR3.
    let task = match unsafe {
        sched::live::spawn_user_thread(
            0xC0DE_0001, "elf-user",
            img.entry.as_u64(),
            new_sp,
            mm,
        )
    } {
        Ok(t)  => t,
        Err(_) => { debug_irq! { klog::kerror!("elf-smoke: spawn failed"); } halt_forever(); }
    };

    // Install init's fd table — fd 0/1/2 → /dev/console (P2-30a).
    let fdt = crate::dev::console::init_console_fd_table();
    // SAFETY: task isn't yet scheduled (we just spawned it); we are sole writer.
    unsafe { task.replace_fd_table(Some(fdt)); }
    let _task = task;

    debug_irq! {
        klog::write_raw(b"[INFO]  elf-smoke: spawned tid=0xC0DE0001 entry=");
        klog::write_hex_u64(img.entry.as_u64());
        klog::write_raw(b" sp=");
        klog::write_hex_u64(new_sp);
        klog::write_raw(b"\n");
    }

    // Pre-fill the TTY ringbuffer with a test byte so the third
    // iteration's ECHO program (P3-02) can read+write a byte
    // non-interactively. Real interactive use rides on UART RX
    // bytes pushed via `tty::tick_poll_uart` from the timer ISR.
    crate::tty::inject_for_smoke(b"A");

    // STI so timer IRQs can drive preempt-on-IRQ-exit if the
    // task ever yields back to kernel; our smoke task runs IF=0
    // through to its first sys_exit so this is a no-op for now.
    // SAFETY: STI legal at CPL=0; pairs with the boot-path discipline that masked IRQs at entry; the runqueue + IRQ epilogue tolerate timer-driven preemption.
    unsafe { core::arch::asm!("sti", options(nomem, nostack)); }
    // schedule() picks the user task (lowest vruntime in CFS),
    // updates current, and Context::switch's into the synthetic
    // iretq frame → drop to ring 3 at e_entry. User runs to ud2
    // landmark; #UD halts in the smoke fault handler.
    // SAFETY: process ctx; runqueue installed; preempt-off.
    unsafe { sched::live::schedule(); }

    // Boot resumes here when the user task exits via `sys_exit`
    // (P2-13d): kernel_sys_exit marks the task Zombie + reschedules,
    // picker returns to idle (boot anchor), Context::switch lands
    // back here on boot's saved regs.
    debug_irq! {
        klog::kinfo!("elf-smoke: user task exited cleanly, boot resumed");
    }

    // Re-arm the LAPIC periodic timer for the real userspace boot
    // path. The canary + preempt smokes both disarm the timer at
    // teardown (`timer_disarm()`), so by the time we reach init the
    // timer is silent. Without it, no timer IRQ ever fires while
    // user tasks run → no preemption + no `tick_poll_uart` → login
    // parks on read(0) forever.
    // SAFETY: LAPIC was previously enabled by smoke_device_map_x86;
    // re-arming the periodic timer at the same period the smokes used.
    #[cfg(target_arch = "x86_64")]
    unsafe { let _ = crate::lapic::timer_periodic(1_000_000); }
    // SAFETY: STI legal at CPL=0; spawn_user_blob_smoke's first
    // schedule() drops to ring 3 with IF=1 in the iretq frame, so
    // both kernel idle (between user task slices) and user mode
    // see timer IRQs.
    unsafe { core::arch::asm!("sti", options(nomem, nostack)); }

    // PID 1: load /sbin/init from the mounted rootfs ext4. /sbin/init
    // is a hardlink to /bin/busybox; busybox's `init` applet reads
    // /etc/inittab, runs the sysinit script, and respawns the
    // console shell. No bespoke PID 1 in this tree — the kernel
    // and image are ours, the userspace is upstream.
    // PID 1 must exist on the rootfs. Per 51§2 invariant 1 the
    // kernel does not embed a fallback init blob in v1.
    let init_blob_opt = lookup_blob_by_path(b"/sbin/init")
        .or_else(|| lookup_blob_by_path(b"/init"));
    hal::kassert!(init_blob_opt.is_some(),
        "no /sbin/init or /init in rootfs (51§2 invariant 1)");
    let init_blob = init_blob_opt.unwrap_or(b"");
    // Linux kernel convention: PID 1 is started with argv[0] =
    // "/sbin/init" so the binary (esp. multi-call binaries like
    // busybox) dispatches the right applet.
    // busybox-init refuses to run unless getpid()==1. Stamp
    // vtgid=1 / vtid=1 on the Task BEFORE it's visible via the
    // registry or runqueue — `spawn_user_blob_with_vpid` writes
    // them on the local Task before Arc-wrap + insert + enqueue,
    // so any concurrent reader (including the very first syscall
    // from this task) sees PID 1.
    // SAFETY: boot-path discipline; user_as / runqueue installed.
    unsafe {
        spawn_user_blob_with_vpid(
            init_blob, "init",
            0xC0DE_0002, /* vtgid */ 1, /* vtid */ 1,
            &[b"/sbin/init" as &[u8]],
        );
    }
    // No second sh fallback: init→svcd→agetty→login→sh is the
    // real chain and login has its own `/bin/sh` exec on success.
    // A boot-path sh competing for /dev/console is harmful now —
    // it eats keystrokes meant for login.

    // No halt: schedule forever, with IRQs on so the timer-tick
    // UART poll keeps draining bytes into the tty rx ringbuffer
    // (which is what wakes login/sh from sys_read). Pre-fix we
    // looped on bare schedule() with IF=0 inherited from the
    // dispatch path — login parked forever because no IRQ ever
    // delivered the keystrokes the user typed.
    // SAFETY: STI is idempotent; the periodic timer was armed
    // before init spawn so this just guarantees IF=1 here in case
    // any spawn path masked IRQs on its way out.
    loop {
        // SAFETY: dispatch ctx; runqueue installed; preempt-off.
        unsafe { sched::live::schedule(); }
        // SAFETY: ctxsw may return with IF in any state (kernel-mode
        // syscall paths run IF=0 via FMASK; we may be resuming on the
        // back of a syscall return). Re-arm IF before the hlt so the
        // CPU can actually be woken by the next timer / device IRQ.
        // Without this, ctxsw-back-to-boot from a parked task can land
        // here with IF=0 and the hlt becomes a permanent stop.
        // SAFETY: enable IRQs + halt waits for the next timer / device IRQ; well-defined at CPL=0; preempt-off across the asm.
        unsafe { core::arch::asm!("sti; hlt", options(nomem, nostack, preserves_flags)); }
    }
}

/// Spawn a static-PIE musl blob as a user task with /dev/console
/// fd 0/1/2, schedule into it, return when it exits via sys_exit.
/// Reused by P5-01 (real-init), P5-02 (tiny sh), and future
/// userspace smokes.
///
/// # SAFETY: caller is post-elf-smoke; user_as installed;
/// runqueue installed; allocator up; per-CPU page set.
/// # C: O(phdrs) parse + O(log N) enqueue
/// # Ctx: post-elf-smoke; preempt-off
unsafe fn spawn_user_blob_smoke(
    blob:    &'static [u8],
    name:    &'static str,
    tid:     u32,
    argv:    &[&[u8]],
) {
    // SAFETY: vpid_tgid=0 / vpid_tid=0 means "no namespace remap" — equivalent to the bare spawn_user_thread the elf-smoke and dynlink callers used historically.
    unsafe { spawn_user_blob_with_vpid(blob, name, tid, 0, 0, argv) }
}

/// Variant of `spawn_user_blob_smoke` that stamps explicit
/// `vtgid` / `vtid` on the spawned task before it's enqueued.
/// Used by the PID 1 spawn path to make `getpid()` /
/// `set_tid_address()` report Linux PID 1 from the very first
/// syscall (musl crt1's `__init_main_thread` caches the
/// set_tid_address return as `__libc.tid`).
///
/// # SAFETY: same preconditions as `spawn_user_blob_smoke`.
/// # C: O(phdrs) parse + O(log N) enqueue
unsafe fn spawn_user_blob_with_vpid(
    blob:      &'static [u8],
    name:      &'static str,
    tid:       u32,
    vpid_tgid: u32,
    vpid_tid:  u32,
    argv:      &[&[u8]],
) {
    use vmm::{AddressSpace, VmaBacking, VmaFlags, VmaProt};
    use hal::{MmuOps, UserVirtAddr};

    // Fresh per-task AS so back-to-back smokes don't overlap PIE
    // pages. Kernel-half is shared (entries 256..512 copied from
    // the master PML4); user-half starts empty.
    // SAFETY: post-PMM init; new_user_pml4 returns a freshly
    // allocated frame zeroed + populated with the kernel half.
    let root_pa = match unsafe { hal_x86_64::mmu_ops::new_user_pml4() } {
        Some(p) => p,
        None    => {
            debug_irq! { klog::kerror!("user-blob: new_user_pml4 failed"); }
            return;
        }
    };
    let mm = match AddressSpace::new(root_pa) {
        Ok(a)  => a,
        Err(_) => {
            debug_irq! { klog::kerror!("user-blob: AddressSpace::new failed"); }
            return;
        }
    };

    // Activate the new AS BEFORE load_static_blob — that function
    // applies DT_RELA self-relocations by writing through user
    // VAs (e.g. 0x10003000 GOT slots). Those writes only land
    // in the right page table if the task's AS is the active CR3;
    // otherwise the kernel page-faults on a not-present user page
    // in whatever AS happened to be active. Pre-fix this worked
    // by luck when the previous task's AS had compatible pages
    // mapped at the same VAs.
    // SAFETY: per-AS PML4 was constructed with kernel-half shared from master so kernel mappings remain valid; CR3 swap legal at CPL=0 IRQ-off.
    unsafe { <hal_x86_64::mmu_ops::X86Mmu as MmuOps>::activate(root_pa); }

    let img = match (|| -> Result<_, elf_load::LoadError> {
        let img = load_static_blob(blob, &mm)?;
        let stack_hint = UserVirtAddr::new(USER_STACK_VA)
            .ok_or(elf_load::LoadError::Einval)?;
        mm.mmap(
            Some(stack_hint), USER_STACK_LEN as usize,
            VmaProt::READ | VmaProt::WRITE,
            VmaFlags::PRIVATE | VmaFlags::ANONYMOUS,
            VmaBacking::Anonymous,
            true,
        ).map_err(|_| elf_load::LoadError::Enomem)?;
        // F152-2: no kernel-side TLS region — user crt1 mmaps its
        // own TCB and installs FS_BASE via arch_prctl(ARCH_SET_FS).
        Ok(img)
    })() {
        Ok(i)  => i,
        Err(_) => {
            debug_irq! { klog::write_raw(b"[ERROR] user-blob load failed: "); klog::write_raw(name.as_bytes()); klog::write_raw(b"\n"); }
            return;
        }
    };

    let random16 = {
        use hal::TimerOps;
        let ns = hal_x86_64::X86TimerOps::monotonic_ns().0;
        let mut r = [0u8; 16];
        for i in 0..16 { r[i] = (ns >> ((i % 8) * 8)) as u8 ^ (i as u8 * 0x9b); }
        r
    };
    // Default argv = ['/init']; otherwise caller-provided.
    let default_argv: &[&[u8]] = &[b"/init"];
    let argv_ref: &[&[u8]] = if argv.is_empty() { default_argv } else { argv };
    // SAFETY: per-task AS just activated; build_user_stack writes through it; demand-fault resolves the new stack page.
    let new_sp = unsafe {
        elf_load::stack::build_user_stack(
            USER_STACK_TOP,
            argv_ref, &[],
            &img,
            &random16,
            argv_ref.first().copied().unwrap_or(b""),
        )
    }.unwrap_or(USER_STACK_TOP);

    // SAFETY: runqueue installed; mm matches active CR3; entry/sp in user range; vpid stamped pre-enqueue so musl's __init_main_thread sees PID 1 on its very first syscall.
    let task = match unsafe {
        sched::live::spawn_user_thread_with_vpid(
            tid, vpid_tgid, vpid_tid, name, img.user_ip(), new_sp, mm,
        )
    } {
        Ok(t)  => t,
        Err(_) => { debug_irq! { klog::kerror!("user-blob: spawn failed"); } return; }
    };

    let fdt = crate::dev::console::init_console_fd_table();
    // SAFETY: task isn't yet scheduled; we are sole writer.
    unsafe { task.replace_fd_table(Some(fdt)); }
    let _task = task;

    // F152-2: leave FS_BASE = 0 on first user entry. musl crt1's
    // __init_tls calls arch_prctl(ARCH_SET_FS, tcb) before any
    // FS-relative access, matching Linux execve semantics.
    // SAFETY: wrmsr IA32_FS_BASE = 0 at CPL=0 is legal; user crt1
    // overwrites with the real TCB before first FS-relative load.
    unsafe { hal_x86_64::set_user_fs_base(0); }

    debug_irq! {
        klog::write_raw(b"[INFO]  user-blob: spawned name=");
        klog::write_raw(name.as_bytes());
        klog::write_raw(b"\n");
    }

    // schedule() into the user task. Returns to the boot anchor
    // when (a) the task exits via sys_exit, or (b) the task
    // parks (e.g. blocks on `read`) and no other runnable task
    // is on this CPU's runqueue. In case (b), the boot caller's
    // `halt_forever()` (sti+hlt loop) keeps timer IRQs firing,
    // which drains UART RX + wakes the parked task next round.
    // SAFETY: process ctx; runqueue installed; preempt-off.
    unsafe { sched::live::schedule(); }
}

/// Parse + load + drop to ring 3 directly (no Task wrapper).
/// Diverges. Retained for the boot path that hasn't yet
/// installed a runqueue (or for debugging).
///
/// # SAFETY: caller is the boot path; user_as::init has run; PMM
/// + MmuOps + GDT + TSS + IDT + syscall MSRs all initialised;
/// single-CPU; IRQs masked.
/// # C: O(phdrs) parse + O(1) drop
/// # Ctx: pre-init, IRQ-off, single-CPU; diverges
pub unsafe fn run(hhdm_offset: u64) -> ! {
    use vmm::{VmaBacking, VmaFlags, VmaProt};
    use hal::UserVirtAddr;

    // 1. Load the ELF into the global AS.
    let img = match crate::user_as::with(|as_| load_static_blob(ELF_BLOB, as_)) {
        Some(Ok(i))  => i,
        Some(Err(e)) => {
            debug_irq! {
                klog::write_raw(b"[FAULT] elf-smoke: load failed err=");
                klog::write_dec_u64(e as u64);
                klog::write_raw(b"\n");
            }
            let _ = e;
            halt_forever();
        }
        None => {
            debug_irq! { klog::kerror!("elf-smoke: user_as not initialised"); }
            halt_forever();
        }
    };

    debug_irq! {
        klog::write_raw(b"[INFO]  elf-smoke: load ok entry=");
        klog::write_hex_u64(img.entry.as_u64());
        klog::write_raw(b" brk=");
        klog::write_hex_u64(img.brk.as_u64());
        klog::write_raw(b"\n");
    }

    // 2. Register an anonymous user-stack VMA. Demand-paging
    //    on first push gives us a fresh zeroed frame.
    let stack_hint = match UserVirtAddr::new(USER_STACK_VA) {
        Some(u) => u,
        None    => { debug_irq! { klog::kerror!("elf-smoke: bad stack VA"); } halt_forever(); }
    };
    let stack_r = crate::user_as::with(|as_| {
        as_.mmap(
            Some(stack_hint), USER_STACK_LEN as usize,
            VmaProt::READ | VmaProt::WRITE,
            VmaFlags::PRIVATE | VmaFlags::ANONYMOUS,
            VmaBacking::Anonymous,
            true,                          // MAP_FIXED at USER_STACK_VA
        )
    });
    if !matches!(stack_r, Some(Ok(_))) {
        debug_irq! { klog::kerror!("elf-smoke: stack mmap failed"); }
        halt_forever();
    }

    // 3. Drop to ring 3 at e_entry. iretq's instruction-fetch at
    //    `entry` will take a #PF that user_as_fault_handler
    //    resolves via the KernelBytes-backed VMA — that's the
    //    real demand-page path the spec wants.
    // SAFETY: GDT/TSS/IDT/syscall MSRs initialised by kernel_main; entry & stack VMAs registered above; CPL=0; IRQs masked.
    unsafe {
        crate::userspace_smoke::drop_to_ring3(
            img.user_ip(),
            USER_STACK_TOP,
            hhdm_offset,
            elf_smoke_fault_handler,
        );
    }
}

fn halt_forever() -> ! {
    // sti+hlt — boot CPU keeps taking timer IRQs so the user
    // shell parked on `read(fd=0)` wakes when UART RX bytes
    // arrive (timer ISR's `tick_poll_uart` drains stdin into
    // RX_BUF). cli+hlt would kill input forever.
    loop {
        // SAFETY: STI legal at CPL=0; HLT parks until next IRQ; combined they idle while IF=1 so timer IRQs fire and tasks can be scheduled back in.
        unsafe { core::arch::asm!("sti; hlt", options(nomem, nostack, preserves_flags)); }
    }
}
