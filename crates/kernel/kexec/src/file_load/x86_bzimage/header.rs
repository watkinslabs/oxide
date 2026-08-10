// `bzImage64_probe` and the setup-header fields the layout needs.
//
// Ungated on purpose. The probe is the whole of "is this a kernel I can
// start"; every one of its refusals is `ENOEXEC`, and getting one of them
// backwards either refuses a bootable image or accepts one that halts the
// machine on the far side of a `reboot(2)` with nothing left to report it.

use super::uapi::*;
use crate::validate::{Error, KResult};

/// The setup-header fields the loader reads, decoded from the file.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SetupHeader {
    /// Real-mode setup sectors after the boot sector, already defaulted.
    pub setup_sects: u64,
    /// Boot-protocol version.
    pub version: u16,
    /// `loadflags`.
    pub loadflags: u8,
    /// `xloadflags`.
    pub xloadflags: u16,
    /// Longest command line this kernel accepts, excluding the NUL.
    pub cmdline_size: u32,
    /// Required alignment of the kernel's destination.
    pub kernel_alignment: u64,
    /// Where the kernel would rather land.
    pub pref_address: u64,
    /// Memory the kernel needs at its destination while it unpacks itself.
    pub init_size: u64,
    /// Bytes of setup header present, `0x202 + jump_offset - BP_HDR`.
    pub header_size: usize,
}

fn u8_at(k: &[u8], o: usize) -> KResult<u8> { k.get(o).copied().ok_or(Error::NoExec) }

fn u16_at(k: &[u8], o: usize) -> KResult<u16> {
    let b = k.get(o..o + 2).ok_or(Error::NoExec)?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

fn u32_at(k: &[u8], o: usize) -> KResult<u32> {
    let b = k.get(o..o + 4).ok_or(Error::NoExec)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn u64_at(k: &[u8], o: usize) -> KResult<u64> {
    let b = k.get(o..o + 8).ok_or(Error::NoExec)?;
    Ok(u64::from_le_bytes(b.try_into().map_err(|_| Error::NoExec)?))
}

/// `bzImage64_probe`, in the reference's order and with its errno.
///
/// The order is the contract, not a style: a file too short to hold a header
/// must be refused BEFORE any field of that header is read, and each later test
/// assumes the earlier ones passed. Two of the reference's tests have no
/// counterpart here and their absence is deliberate, not an omission — the
/// 32-bit-EFI refusal cannot fire on a port with no EFI runtime services, and
/// the `XLF_5LEVEL` refusal cannot fire on a port that does not enable 5-level
/// paging. Both would refuse an image this machine can start.
/// # C: O(1)
pub fn probe(kernel: &[u8]) -> KResult<()> {
    if kernel.len() < MIN_FILE_LEN { return Err(Error::NoExec); }
    if kernel.get(HDR_MAGIC..HDR_MAGIC + 4) != Some(&MAGIC[..]) { return Err(Error::NoExec); }
    if u16_at(kernel, HDR_BOOT_FLAG)? != BOOT_FLAG { return Err(Error::NoExec); }
    if u16_at(kernel, HDR_VERSION)? < MIN_VERSION { return Err(Error::NoExec); }
    if u8_at(kernel, HDR_LOADFLAGS)? & LOADED_HIGH == 0 { return Err(Error::NoExec); }
    let xlf = u16_at(kernel, HDR_XLOADFLAGS)?;
    if xlf & XLF_KERNEL_64 == 0 { return Err(Error::NoExec); }
    if xlf & XLF_CAN_BE_LOADED_ABOVE_4G == 0 { return Err(Error::NoExec); }
    Ok(())
}

impl SetupHeader {
    /// Decode the fields the layout needs. Call only on a file `probe` accepted.
    /// # C: O(1)
    pub fn parse(kernel: &[u8]) -> KResult<Self> {
        let sects = match u8_at(kernel, HDR_SETUP_SECTS)? {
            0 => DEFAULT_SETUP_SECTS,
            n => n as u64,
        };
        let jump = u8_at(kernel, HDR_JUMP_OFFSET)? as usize;
        Ok(Self {
            setup_sects: sects,
            version: u16_at(kernel, HDR_VERSION)?,
            loadflags: u8_at(kernel, HDR_LOADFLAGS)?,
            xloadflags: u16_at(kernel, HDR_XLOADFLAGS)?,
            cmdline_size: u32_at(kernel, HDR_CMDLINE_SIZE)?,
            kernel_alignment: u32_at(kernel, HDR_KERNEL_ALIGNMENT)? as u64,
            pref_address: u64_at(kernel, HDR_PREF_ADDRESS)?,
            init_size: u32_at(kernel, HDR_INIT_SIZE)? as u64,
            header_size: (HDR_MAGIC + jump).saturating_sub(BP_HDR),
        })
    }

    /// Bytes of real-mode code at the front of the file, which the 64-bit
    /// loader does not carry: `(setup_sects + 1) * 512`.
    /// # C: O(1)
    pub fn kern16_size(&self) -> u64 { (self.setup_sects + 1) * SECTOR_SIZE }

    /// Lowest address the kernel segment may occupy.
    /// # C: O(1)
    pub fn kernel_min(&self) -> u64 {
        if self.pref_address < MIN_KERNEL_LOAD_ADDR { MIN_KERNEL_LOAD_ADDR } else { self.pref_address }
    }

    /// `EINVAL` when the command line does not fit, including the room the
    /// reference reserves for an appended `elfcorehdr=`.
    ///
    /// `len` counts the terminating NUL, which is what the field bounds.
    /// # C: O(1)
    pub fn cmdline_fits(&self, len: usize) -> KResult<()> {
        if len > self.cmdline_size as usize { return Err(Error::Inval); }
        if len + MAX_ELFCOREHDR_STR_LEN > self.cmdline_size as usize { return Err(Error::Inval); }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::vec;
    use alloc::vec::Vec;

    /// A minimal file that `probe` accepts, so each test can break exactly one
    /// field and watch the refusal move.
    fn good() -> Vec<u8> {
        let mut k = vec![0u8; 0x1000];
        k[HDR_SETUP_SECTS] = 4;
        k[HDR_JUMP_OFFSET] = 0x6a;
        k[HDR_BOOT_FLAG..HDR_BOOT_FLAG + 2].copy_from_slice(&BOOT_FLAG.to_le_bytes());
        k[HDR_MAGIC..HDR_MAGIC + 4].copy_from_slice(&MAGIC);
        k[HDR_VERSION..HDR_VERSION + 2].copy_from_slice(&0x020fu16.to_le_bytes());
        k[HDR_LOADFLAGS] = LOADED_HIGH;
        k[HDR_XLOADFLAGS..HDR_XLOADFLAGS + 2]
            .copy_from_slice(&(XLF_KERNEL_64 | XLF_CAN_BE_LOADED_ABOVE_4G).to_le_bytes());
        k[HDR_CMDLINE_SIZE..HDR_CMDLINE_SIZE + 4].copy_from_slice(&0x7ffu32.to_le_bytes());
        k[HDR_KERNEL_ALIGNMENT..HDR_KERNEL_ALIGNMENT + 4]
            .copy_from_slice(&0x200000u32.to_le_bytes());
        k[HDR_PREF_ADDRESS..HDR_PREF_ADDRESS + 8].copy_from_slice(&0x1000000u64.to_le_bytes());
        k[HDR_INIT_SIZE..HDR_INIT_SIZE + 4].copy_from_slice(&0x4aea000u32.to_le_bytes());
        k
    }

    #[test]
    fn every_probe_refusal_is_enoexec_and_fires_on_its_own_field() {
        assert_eq!(probe(&good()), Ok(()));

        let mut short = good();
        short.truncate(MIN_FILE_LEN - 1);
        assert_eq!(probe(&short), Err(Error::NoExec), "a file shorter than two sectors");

        let mut k = good();
        k[HDR_MAGIC] = b'X';
        assert_eq!(probe(&k), Err(Error::NoExec), "the HdrS signature");

        let mut k = good();
        k[HDR_BOOT_FLAG] = 0;
        assert_eq!(probe(&k), Err(Error::NoExec), "the 0xAA55 boot flag");

        let mut k = good();
        k[HDR_VERSION..HDR_VERSION + 2].copy_from_slice(&0x020bu16.to_le_bytes());
        assert_eq!(probe(&k), Err(Error::NoExec), "protocol 2.11 is below the floor");
        let mut k = good();
        k[HDR_VERSION..HDR_VERSION + 2].copy_from_slice(&MIN_VERSION.to_le_bytes());
        assert_eq!(probe(&k), Ok(()), "protocol 2.12 is exactly at the floor");

        let mut k = good();
        k[HDR_LOADFLAGS] = 0;
        assert_eq!(probe(&k), Err(Error::NoExec), "a zImage, not a bzImage");

        let mut k = good();
        k[HDR_XLOADFLAGS..HDR_XLOADFLAGS + 2]
            .copy_from_slice(&XLF_CAN_BE_LOADED_ABOVE_4G.to_le_bytes());
        assert_eq!(probe(&k), Err(Error::NoExec), "no 64-bit entry point");

        let mut k = good();
        k[HDR_XLOADFLAGS..HDR_XLOADFLAGS + 2].copy_from_slice(&XLF_KERNEL_64.to_le_bytes());
        assert_eq!(probe(&k), Err(Error::NoExec), "cannot be loaded above 4 GiB");
    }

    #[test]
    fn setup_sects_of_zero_means_four_sectors() {
        // Older than the header: a zero here is not "no setup", it is four.
        // Reading it literally makes the kernel segment start 2 KiB early, and
        // the image boots into the middle of the real-mode stub.
        let mut k = good();
        k[HDR_SETUP_SECTS] = 0;
        assert_eq!(SetupHeader::parse(&k).expect("well formed").setup_sects, 4);
        assert_eq!(SetupHeader::parse(&k).expect("well formed").kern16_size(), 5 * 512);
        let h = SetupHeader::parse(&good()).expect("well formed");
        assert_eq!(h.kern16_size(), 5 * 512);
    }

    #[test]
    fn the_kernel_floor_is_the_higher_of_one_mib_and_pref_address() {
        let mut k = good();
        k[HDR_PREF_ADDRESS..HDR_PREF_ADDRESS + 8].copy_from_slice(&0u64.to_le_bytes());
        assert_eq!(SetupHeader::parse(&k).expect("wf").kernel_min(), MIN_KERNEL_LOAD_ADDR);
        assert_eq!(SetupHeader::parse(&good()).expect("wf").kernel_min(), 0x1000000);
    }

    #[test]
    fn the_command_line_must_leave_room_for_an_appended_elfcorehdr() {
        // A command line that fits exactly is still refused: a crash image
        // appends `elfcorehdr=0x…` to it, and the reference reserves that room
        // on every image so the test does not depend on the image type.
        let h = SetupHeader::parse(&good()).expect("wf");
        let max = h.cmdline_size as usize;
        assert_eq!(h.cmdline_fits(max - MAX_ELFCOREHDR_STR_LEN), Ok(()));
        assert_eq!(h.cmdline_fits(max - MAX_ELFCOREHDR_STR_LEN + 1), Err(Error::Inval));
        assert_eq!(h.cmdline_fits(max + 1), Err(Error::Inval));
    }

    #[test]
    fn the_setup_header_length_comes_from_the_jump_instructions_operand() {
        // `0x202 + kernel[0x201] - 0x1F1`. Getting this wrong copies either
        // half a header into the boot parameters or bytes past its end.
        let h = SetupHeader::parse(&good()).expect("wf");
        assert_eq!(h.header_size, 0x202 + 0x6a - 0x1F1);
        assert!(BP_HDR + h.header_size <= BP_SIZE);
        // It must at least cover `init_size`, the last field the loader reads.
        assert!(BP_HDR + h.header_size >= HDR_INIT_SIZE + 4);
    }

    /// The Fedora rescue kernel on this machine, when it is present. A test
    /// that only ever sees a hand-built header cannot catch a field this port
    /// placed at an offset the protocol does not use.
    fn real_bzimage() -> Option<(Vec<u8>, usize)> {
        use std::io::Read;
        let dir = "/home/nd/oxide/images/build/lite-x86_64-root/boot";
        let entries = std::fs::read_dir(dir).ok()?;
        for e in entries.flatten() {
            let name = e.file_name();
            let name = name.to_string_lossy();
            if !name.starts_with("vmlinuz-") { continue; }
            let mut f = std::fs::File::open(e.path()).ok()?;
            let len = f.metadata().ok()?.len() as usize;
            let mut buf = vec![0u8; 0x1000];
            f.read_exact(&mut buf).ok()?;
            return Some((buf, len));
        }
        None
    }

    #[test]
    fn a_real_fedora_bzimage_probes_and_decodes() {
        let Some((k, k_len)) = real_bzimage() else {
            // Absent fixture must not silently pass as a green test.
            std::eprintln!("SKIPPED: no vmlinuz- fixture on this machine");
            return;
        };
        assert_eq!(probe(&k), Ok(()), "a shipping Fedora kernel must be loadable");
        let h = SetupHeader::parse(&k).expect("a probed file decodes");
        // Values read out of the file itself, not asserted as constants: what
        // is pinned is that each lands in the field the protocol names.
        assert!(h.version >= MIN_VERSION);
        assert_eq!(h.loadflags & LOADED_HIGH, LOADED_HIGH);
        assert_eq!(h.xloadflags & (XLF_KERNEL_64 | XLF_CAN_BE_LOADED_ABOVE_4G),
                   XLF_KERNEL_64 | XLF_CAN_BE_LOADED_ABOVE_4G);
        assert!(h.kernel_alignment.is_power_of_two(), "alignment {:#x}", h.kernel_alignment);
        assert!(h.kernel_alignment >= 0x1000);
        // `init_size` is the memory the kernel needs while unpacking itself,
        // so it cannot be smaller than the compressed image it unpacks. A
        // neighbouring field read by mistake fails this.
        assert!(h.init_size >= k_len as u64,
                "init_size {:#x} is below the image size {:#x}", h.init_size, k_len);
        assert!(h.pref_address >= MIN_KERNEL_LOAD_ADDR);
        assert!(h.cmdline_size >= 255);
        assert!(h.setup_sects >= 1 && h.setup_sects <= 64);
        assert!(BP_HDR + h.header_size <= BP_SIZE);
        assert!(BP_HDR + h.header_size >= HDR_INIT_SIZE + 4);
    }
}
