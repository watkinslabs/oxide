# Windows NT volume information

FROZEN 2026-09-01. Dep: 01,02,16,31h,52,53. Provides native NtQueryVolumeInformationFile translation over the owning VFS mount.

## 1 Contract

- The NT file handle resolves to its captured VFS mount and inode.
- Filesystem accounting comes from SuperBlock::statfs_at; NT code does not
  re-walk a pathname or inspect Linux host paths.
- Device, size, full-size, volume, and attribute information classes preserve
  fixed Windows field widths and report the bytes written through the I/O
  status block.
- A short output buffer reports STATUS_BUFFER_TOO_SMALL without writing the
  output payload.
- Unsupported information classes report STATUS_INVALID_INFO_CLASS.
- Linux file and statfs paths remain unchanged.

## 2 Translation

| NT class | VFS source |
|---|---|
| FileFsDeviceInformation | disk device identity |
| FileFsSizeInformation | f_blocks, f_bavail, f_bsize |
| FileFsFullSizeInformation | f_blocks, f_bavail, f_bsize |
| FileFsVolumeInformation | f_fsid |
| FileFsAttributeInformation | filesystem identity and name limits |

Allocation units use the VFS block size with 512-byte sectors. Attribute
filesystem names map known CDFS, UDF, and FAT32 identities; other filesystems
use the NTFS-compatible name expected by the runtime provider.

## 3 Tests

- direct NT arguments decode into a volume query without an intermediate
  request record;
- device and size encoders preserve the Windows layouts;
- unsupported classes do not become success;
- the complete Windows compatibility suite and both kernel targets pass.
