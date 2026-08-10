// User-memory access for the seccomp install path. Every copy goes through
// `uaccess`, whose hand-written loops carry the exception-table fixups: a
// range check alone proves only that an address is in the user half, so
// dereferencing one raw faults the kernel for any address a program is free
// to pass. Nothing here decides an errno beyond EFAULT; the ladder lives in
// `install.rs`.

use alloc::vec::Vec;
use syscall::errno::Errno;

use super::insn::SockFilter;
use super::uapi::*;

/// `copy_from_user(&fprog, user_filter, sizeof(fprog))` — `struct sock_fprog
/// { unsigned short len; struct sock_filter *filter; }`, 16 bytes on 64-bit
/// with the pointer at offset 8.
/// # C: O(1)
pub fn read_fprog(uptr: u64) -> Result<(u16, u64), Errno> {
    let mut raw = [0u8; SOCK_FPROG_BYTES as usize];
    uaccess::copy_from_user(&mut raw, uptr)?;
    let len = u16::from_ne_bytes([raw[0], raw[1]]);
    let off = SOCK_FPROG_FILTER_OFF as usize;
    let mut ptr = [0u8; 8];
    ptr.copy_from_slice(&raw[off..off + 8]);
    Ok((len, u64::from_ne_bytes(ptr)))
}

/// Copy `len` `struct sock_filter` entries into the packed-u64 form the
/// interpreter runs. Caller has already bounded `len` by `BPF_MAXINSNS`.
/// The whole program travels in one copy, as `bpf_prog_create_from_user`
/// does, so a program straddling an unmapped page is a single EFAULT rather
/// than a partially-decoded filter.
/// # C: O(len)
pub fn read_prog(filter_p: u64, len: usize) -> Result<Vec<u64>, Errno> {
    let bytes = (len as u64).checked_mul(SOCK_FILTER_BYTES).ok_or(Errno::Efault)?;
    let mut raw = alloc::vec![0u8; bytes as usize];
    uaccess::copy_from_user(&mut raw, filter_p)?;
    let mut prog: Vec<u64> = Vec::with_capacity(len);
    for i in 0..len {
        let f = &raw[i * SOCK_FILTER_BYTES as usize..];
        prog.push(SockFilter::new(
            u16::from_ne_bytes([f[0], f[1]]),
            f[2],
            f[3],
            u32::from_ne_bytes([f[4], f[5], f[6], f[7]])).encode());
    }
    Ok(prog)
}

/// `copy_from_user(&action, uaction, sizeof(action))` for
/// `SECCOMP_GET_ACTION_AVAIL`.
/// # C: O(1)
pub fn read_u32(uptr: u64) -> Result<u32, Errno> {
    let mut raw = [0u8; 4];
    uaccess::copy_from_user(&mut raw, uptr)?;
    Ok(u32::from_ne_bytes(raw))
}

/// `copy_to_user(usizes, &sizes, sizeof(sizes))` for
/// `SECCOMP_GET_NOTIF_SIZES`: `struct seccomp_notif_sizes { __u16
/// seccomp_notif, seccomp_notif_resp, seccomp_data; }`.
/// # C: O(1)
pub fn write_notif_sizes(uptr: u64, sizes: [u16; 3]) -> Result<(), Errno> {
    let mut raw = [0u8; 6];
    for (i, v) in sizes.iter().copied().enumerate() {
        raw[i * 2..i * 2 + 2].copy_from_slice(&v.to_ne_bytes());
    }
    uaccess::copy_to_user(uptr, &raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn efault<T: core::fmt::Debug>(r: Result<T, Errno>) { assert_eq!(r.unwrap_err(), Errno::Efault); }

    /// A pointer the copy refuses is EFAULT, not a kernel fault. `read_prog`
    /// with a zero-length program still refuses a null pointer only when the
    /// copy would touch it.
    #[test]
    fn every_reader_answers_efault_for_a_pointer_the_copy_refuses() {
        efault(read_fprog(0));
        efault(read_fprog(hal::USER_VA_END));
        efault(read_u32(0));
        efault(read_u32(hal::USER_VA_END - 2));
        efault(read_prog(0, 1));
        efault(read_prog(hal::USER_VA_END - 4, 1));
        efault(write_notif_sizes(0, [1, 2, 3]));
        efault(write_notif_sizes(hal::USER_VA_END - 4, [1, 2, 3]));
    }

    /// `sock_fprog` is `{u16 len; ptr filter;}` with the pointer at offset 8,
    /// so the six padding bytes between them are not part of either member.
    #[test]
    fn the_program_header_reads_the_count_and_the_pointer_past_the_padding() {
        #[repr(C)]
        struct Fprog { len: u16, filter: u64 }
        let insns = [0u64; 2];
        let fp = Fprog { len: 2, filter: insns.as_ptr() as u64 };
        assert_eq!(read_fprog(&fp as *const Fprog as u64).unwrap(), (2, insns.as_ptr() as u64));
    }

    /// Each `sock_filter` is `{u16 code; u8 jt; u8 jf; u32 k;}` packed into
    /// the interpreter's word; a whole program arrives in one copy.
    #[test]
    fn a_program_decodes_every_instruction_field_in_order() {
        let raw: [u8; 16] = [0x06, 0x00, 0x11, 0x22, 0x7f, 0xff, 0x00, 0x00,
                             0x15, 0x00, 0x01, 0x02, 0x2a, 0x00, 0x00, 0x00];
        let prog = read_prog(raw.as_ptr() as u64, 2).unwrap();
        assert_eq!(prog.len(), 2);
        assert_eq!(SockFilter::decode(prog[0]), SockFilter::new(0x0006, 0x11, 0x22, 0x0000_ff7f));
        assert_eq!(SockFilter::decode(prog[1]), SockFilter::new(0x0015, 0x01, 0x02, 0x0000_002a));
    }

    #[test]
    fn the_notification_sizes_land_as_three_consecutive_halfwords() {
        let mut out = [0u16; 3];
        write_notif_sizes(out.as_mut_ptr() as u64, [80, 24, 64]).unwrap();
        assert_eq!(out, [80, 24, 64]);
    }
}
