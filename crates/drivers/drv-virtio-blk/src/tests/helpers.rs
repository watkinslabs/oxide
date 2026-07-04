use super::*;

/// Fake flat memory addressed by the PAs `build_chain` emits.
pub(super) struct FakeMem {
    pub(super) region: Vec<u8>,
    pub(super) disk: Vec<u8>,
}

impl FakeMem {
    pub(super) fn new() -> Self {
        FakeMem { region: vec![0u8; 0x4000], disk: vec![0u8; 512 * 8] }
    }

    pub(super) fn w(&mut self, pa: u64, bytes: &[u8]) {
        let off = pa as usize;
        self.region[off..off + bytes.len()].copy_from_slice(bytes);
    }

    pub(super) fn r(&self, pa: u64, len: usize) -> &[u8] {
        let off = pa as usize;
        &self.region[off..off + len]
    }

    pub(super) fn process(&mut self, descs: &[blk::DescSpec], n: usize) {
        let hdr = self.r(descs[0].addr, 16).to_vec();
        let type_ = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
        let sector = u64::from_le_bytes([
            hdr[8], hdr[9], hdr[10], hdr[11], hdr[12], hdr[13], hdr[14], hdr[15],
        ]);
        let status_desc = descs[n - 1];
        assert_eq!(status_desc.flags & VRING_DESC_F_WRITE, VRING_DESC_F_WRITE);
        if n == 3 {
            let data = descs[1];
            let dlen = data.len as usize;
            let dsec = (sector as usize) * 512;
            if type_ == blk::VIRTIO_BLK_T_IN {
                assert_eq!(data.flags & VRING_DESC_F_WRITE, VRING_DESC_F_WRITE);
                let src = self.disk[dsec..dsec + dlen].to_vec();
                self.w(data.addr, &src);
            } else {
                assert_eq!(data.flags & VRING_DESC_F_WRITE, 0);
                let src = self.r(data.addr, dlen).to_vec();
                self.disk[dsec..dsec + dlen].copy_from_slice(&src);
            }
        }
        self.w(status_desc.addr, &[blk::VIRTIO_BLK_S_OK]);
    }
}

/// FakeMem with a larger scratch region so a multi-sector data desc fits.
pub(super) struct FakeMemBig {
    pub(super) region: Vec<u8>,
    pub(super) disk: Vec<u8>,
}

impl FakeMemBig {
    pub(super) fn new(region_bytes: usize, disk_bytes: usize) -> Self {
        FakeMemBig { region: vec![0u8; region_bytes], disk: vec![0u8; disk_bytes] }
    }

    pub(super) fn w(&mut self, pa: u64, bytes: &[u8]) {
        let off = pa as usize;
        self.region[off..off + bytes.len()].copy_from_slice(bytes);
    }

    pub(super) fn r(&self, pa: u64, len: usize) -> Vec<u8> {
        let off = pa as usize;
        self.region[off..off + len].to_vec()
    }

    pub(super) fn process(&mut self, descs: &[blk::DescSpec], n: usize) {
        let hdr = self.r(descs[0].addr, 16);
        let type_ = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
        let sector = u64::from_le_bytes([
            hdr[8], hdr[9], hdr[10], hdr[11], hdr[12], hdr[13], hdr[14], hdr[15],
        ]);
        let status_desc = descs[n - 1];
        assert_eq!(status_desc.flags & VRING_DESC_F_WRITE, VRING_DESC_F_WRITE);
        if n == 3 {
            let data = descs[1];
            let dlen = data.len as usize;
            let dsec = (sector as usize) * 512;
            if type_ == blk::VIRTIO_BLK_T_IN {
                assert_eq!(data.flags & VRING_DESC_F_WRITE, VRING_DESC_F_WRITE);
                let src = self.disk[dsec..dsec + dlen].to_vec();
                self.w(data.addr, &src);
            } else {
                assert_eq!(data.flags & VRING_DESC_F_WRITE, 0);
                let src = self.r(data.addr, dlen);
                self.disk[dsec..dsec + dlen].copy_from_slice(&src);
            }
        }
        self.w(status_desc.addr, &[blk::VIRTIO_BLK_S_OK]);
    }
}
