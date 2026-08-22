//! Rseq slice-extension debugfs control.

use alloc::format;
use alloc::sync::Arc;

use vfs::file_ops::FileOps;
use vfs::inode::{Inode, InodeBuilder};
use vfs::inode_ops::mk_mode;
use vfs::{FileType, InodeRef, KResult, VfsError};

struct SliceExtensionOps;

fn read_window(body: &[u8], off: u64, buf: &mut [u8]) -> usize {
    let Ok(off) = usize::try_from(off) else { return 0; };
    let Some(body) = body.get(off..) else { return 0; };
    let n = body.len().min(buf.len());
    buf[..n].copy_from_slice(&body[..n]);
    n
}

fn parse_ns(buf: &[u8]) -> Result<u64, VfsError> {
    let text = core::str::from_utf8(buf).map_err(|_| VfsError::Einval)?.trim();
    text.parse::<u32>().map(u64::from).map_err(|_| VfsError::Einval)
}

impl FileOps for SliceExtensionOps {
    fn read(&self, _inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let body = format!("{}\n", sched::rseq_slice::extension_ns());
        Ok(read_window(body.as_bytes(), off, buf))
    }

    fn write(&self, _inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> {
        let ns = parse_ns(buf)?;
        if !sched::rseq_slice::set_extension_ns(ns) { return Err(VfsError::Erange); }
        Ok(buf.len())
    }
}

fn make_inode() -> InodeRef {
    InodeBuilder::new(crate::ring::alloc_control_ino(), mk_mode(FileType::Regular, 0o644),
        crate::ring::control_inode_ops(), Arc::new(SliceExtensionOps))
        .size(6)
        .build()
}

/// Publish `/sys/kernel/debug/rseq/slice_ext_nsec`. # C: O(1)
pub(crate) fn register() {
    crate::register_debug("/sys/kernel/debug/rseq/slice_ext_nsec", make_inode());
}

#[cfg(test)]
mod tests {
    use super::parse_ns;

    #[test]
    fn parser_accepts_decimal_and_rejects_non_u32_values() {
        assert_eq!(parse_ns(b"5000\n"), Ok(5_000));
        assert_eq!(parse_ns(b"+50000"), Ok(50_000));
        assert_eq!(parse_ns(b"nope"), Err(vfs::VfsError::Einval));
        assert_eq!(parse_ns(b"4294967296"), Err(vfs::VfsError::Einval));
    }
}
