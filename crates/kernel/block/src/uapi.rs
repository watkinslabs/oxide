//! Linux block-device UAPI constants (`include/uapi/linux/major.h`).

/// `SCSI_DISK0_MAJOR`: first SCSI disk major. # C: O(1)
pub const SCSI_DISK_MAJOR: u32 = 8;
/// `VIRTBLK_MAJOR`: virtio block device major. # C: O(1)
pub const VIRTIO_BLK_MAJOR: u32 = 253;
/// `BLOCK_EXT_MAJOR`: NVMe namespace extended major. # C: O(1)
pub const NVME_BLK_MAJOR: u32 = 259;
