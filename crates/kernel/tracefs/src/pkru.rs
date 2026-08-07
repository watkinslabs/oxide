//! x86 PKRU debugfs control.

use alloc::format;
use alloc::sync::Arc;

use vfs::file_ops::FileOps;
use vfs::inode::{Inode, InodeBuilder};
use vfs::inode_ops::mk_mode;
use vfs::{FileType, InodeRef, KResult, VfsError};

struct InitPkruOps;

fn read_at(body: &[u8], off: u64, buf: &mut [u8]) -> usize {
    let off = off as usize;
    if off >= body.len() { return 0; }
    let n = (body.len() - off).min(buf.len());
    buf[..n].copy_from_slice(&body[off..off + n]);
    n
}

fn parse_value(buf: &[u8]) -> Result<u32, VfsError> {
    let text = core::str::from_utf8(buf).map_err(|_| VfsError::Einval)?.trim();
    let (text, radix) = if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        (hex, 16)
    } else if text.len() > 1 && text.starts_with('0') {
        let octal = text.strip_prefix('0').unwrap();
        (octal, 8)
    } else {
        (text, 10)
    };
    u32::from_str_radix(text, radix)
        .map_err(|_| VfsError::Einval)
}

impl FileOps for InitPkruOps {
    fn read(&self, _inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let body = format!("0x{:x}\n", hal_x86_64::pkru::pkru_init_value());
        Ok(read_at(body.as_bytes(), off, buf))
    }

    fn write(&self, _inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> {
        let value = parse_value(buf)?;
        hal_x86_64::pkru::set_pkru_init_value(value).map_err(|_| VfsError::Einval)?;
        Ok(buf.len())
    }
}

fn make_inode() -> InodeRef {
    InodeBuilder::new(crate::ring::alloc_control_ino(), mk_mode(FileType::Regular, 0o600),
        crate::ring::control_inode_ops(), Arc::new(InitPkruOps))
        .size(11)
        .build()
}

/// Register the control only when hardware PKU is enabled. # C: O(1)
pub(crate) fn register() {
    if hal_x86_64::pkru::ospke_enabled() {
        crate::register_debug("/sys/kernel/debug/x86/init_pkru", make_inode());
    }
}

#[cfg(test)]
mod tests {
    use super::parse_value;

    #[test]
    fn parser_accepts_debugfs_integer_spellings() {
        assert_eq!(parse_value(b"12\n"), Ok(12));
        assert_eq!(parse_value(b"0xc\n"), Ok(12));
        assert_eq!(parse_value(b"014\n"), Ok(12));
        assert!(parse_value(b"nope").is_err());
    }
}
