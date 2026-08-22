use super::*;

use alloc::sync::Arc;
use alloc::vec::Vec;
use block::{BlockDevice, BlockError, BlockOp, BlockRequest};
use crate::uapi::{IO_REPARSE_TAG_MOUNT_POINT, IO_REPARSE_TAG_NAME_SURROGATE,
                  IO_REPARSE_TAG_SYMLINK, IO_REPARSE_TAG_WOF,
                  REPARSE_OFF_DATA_LEN, REPARSE_OFF_MOUNT_BUFFER,
                  REPARSE_OFF_SYMLINK_SUB_LEN, REPARSE_OFF_TAG};

const THIRD_PARTY_NAME_SURROGATE: u32 = IO_REPARSE_TAG_NAME_SURROGATE | 0x1234;
const THIRD_PARTY_DATA_TAG: u32 = 0x0000_1234;

#[test]
fn every_name_surrogate_presents_as_a_link() {
    assert_eq!(file_type(Some(IO_REPARSE_TAG_SYMLINK), false), FileType::Symlink);
    assert_eq!(file_type(Some(IO_REPARSE_TAG_MOUNT_POINT), true), FileType::Symlink);
    assert_eq!(file_type(Some(THIRD_PARTY_NAME_SURROGATE), false), FileType::Symlink);
}

#[test]
fn an_unknown_data_tag_keeps_the_records_ordinary_type() {
    assert_eq!(file_type(Some(THIRD_PARTY_DATA_TAG), false), FileType::Regular);
    assert_eq!(file_type(Some(THIRD_PARTY_DATA_TAG), true), FileType::Directory);
    assert_eq!(file_type(Some(IO_REPARSE_TAG_WOF), false), FileType::Regular);
}

struct Disk { bytes: Vec<u8> }

impl BlockDevice for Disk {
    fn block_size(&self) -> u32 { crate::test_image::SECTOR as u32 }
    fn capacity_blocks(&self) -> u64 {
        self.bytes.len() as u64 / u64::from(self.block_size())
    }
    fn submit_sync(&self, req: &mut BlockRequest) -> block::KResult<()> {
        if req.op != BlockOp::Read { return Err(BlockError::Eopnotsupp); }
        let at = req.start_block as usize * self.block_size() as usize;
        let len = req.len_blocks as usize * self.block_size() as usize;
        let bytes = self.bytes.get(at..at + len).ok_or(BlockError::Eio)?;
        req.buffer = bytes.to_vec();
        Ok(())
    }
    fn flush(&self) -> block::KResult<()> { Ok(()) }
}

#[test]
fn a_junction_is_a_readable_link_through_the_mounted_vfs_inode() {
    let target: Vec<u8> = r"\??\C:\tree".encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut raw = alloc::vec![0u8; REPARSE_OFF_MOUNT_BUFFER + target.len()];
    let data_len = u16::try_from(raw.len() - 8).unwrap();
    raw[REPARSE_OFF_TAG..REPARSE_OFF_TAG + 4]
        .copy_from_slice(&IO_REPARSE_TAG_MOUNT_POINT.to_le_bytes());
    raw[REPARSE_OFF_DATA_LEN..REPARSE_OFF_DATA_LEN + 2]
        .copy_from_slice(&data_len.to_le_bytes());
    raw[REPARSE_OFF_SYMLINK_SUB_LEN..REPARSE_OFF_SYMLINK_SUB_LEN + 2]
        .copy_from_slice(&(u16::try_from(target.len()).unwrap()).to_le_bytes());
    raw[REPARSE_OFF_MOUNT_BUFFER..].copy_from_slice(&target);

    let mut builder = crate::test_image::Builder::new();
    builder.push_reparse("junction", true, &raw);
    let image = builder.finish();
    let disk = Arc::new(Disk { bytes: image.snapshot() });
    let fs = NtfsFs::open(disk as Arc<dyn BlockDevice>, "/dev/test").expect("mount");
    let inode = fs.root_inode().expect("root").lookup("junction").expect("junction");
    assert_eq!(inode.file_type(), FileType::Symlink);
    assert_eq!(inode.readlink().expect("readlink"), b"/??/C:/tree");
}
