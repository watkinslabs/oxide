// virtio-net per Virtio 1.2 §5.1. Two queues for the simple
// (non-multiqueue) case: rx (queue 0) + tx (queue 1). Optional
// control queue rides P12-04+.
//
// The wire format for tx/rx descriptors is:
//   [ virtio_net_hdr (12 or 10 bytes) | Ethernet frame ]
// Header indicates GSO/checksum offload; v1 uses a zero header
// (no offload) and lets the L4 layer compute checksums.

use crate::queue::VirtQueue;

pub const VIRTIO_NET_HDR_LEN_V1: usize = 12;

/// Net feature bits (subset).
pub const VIRTIO_NET_F_CSUM:    u64 = 1 << 0;
pub const VIRTIO_NET_F_MAC:     u64 = 1 << 5;
pub const VIRTIO_NET_F_MRG_RXBUF: u64 = 1 << 15;
pub const VIRTIO_NET_F_STATUS:  u64 = 1 << 16;

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct VirtioNetHdr {
    pub flags:       u8,
    pub gso_type:    u8,
    pub hdr_len:     u16,
    pub gso_size:    u16,
    pub csum_start:  u16,
    pub csum_offset: u16,
    pub num_buffers: u16,
}

impl VirtioNetHdr {
    /// Serialize into the leading 12 bytes of `buf`.
    /// # C: O(1)
    pub fn write_to(&self, buf: &mut [u8]) {
        buf[0] = self.flags;
        buf[1] = self.gso_type;
        buf[2..4].copy_from_slice(&self.hdr_len.to_le_bytes());
        buf[4..6].copy_from_slice(&self.gso_size.to_le_bytes());
        buf[6..8].copy_from_slice(&self.csum_start.to_le_bytes());
        buf[8..10].copy_from_slice(&self.csum_offset.to_le_bytes());
        buf[10..12].copy_from_slice(&self.num_buffers.to_le_bytes());
    }

    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < VIRTIO_NET_HDR_LEN_V1 { return None; }
        Some(Self {
            flags:       buf[0],
            gso_type:    buf[1],
            hdr_len:     u16::from_le_bytes([buf[2], buf[3]]),
            gso_size:    u16::from_le_bytes([buf[4], buf[5]]),
            csum_start:  u16::from_le_bytes([buf[6], buf[7]]),
            csum_offset: u16::from_le_bytes([buf[8], buf[9]]),
            num_buffers: u16::from_le_bytes([buf[10], buf[11]]),
        })
    }
}

/// Driver-side state for a virtio-net device. Owns rx + tx
/// VirtQueues; the kernel-side wrapper bridges to NetDev::xmit
/// by allocating a buffer, copying payload, alloc_chain on tx,
/// publish.
pub struct VirtioNet {
    pub rx: VirtQueue,
    pub tx: VirtQueue,
    pub mac: [u8; 6],
}

impl VirtioNet {
    pub fn new(qsize: u16, mac: [u8; 6]) -> Self {
        Self { rx: VirtQueue::new(qsize), tx: VirtQueue::new(qsize), mac }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hdr_round_trip() {
        let h = VirtioNetHdr { flags: 0, gso_type: 0, hdr_len: 0, gso_size: 0,
                                csum_start: 0, csum_offset: 0, num_buffers: 1 };
        let mut buf = [0u8; VIRTIO_NET_HDR_LEN_V1];
        h.write_to(&mut buf);
        let p = VirtioNetHdr::parse(&buf).unwrap();
        assert_eq!(h, p);
        assert_eq!(p.num_buffers, 1);
    }

    #[test]
    fn instantiate() {
        let v = VirtioNet::new(8, [1,2,3,4,5,6]);
        assert_eq!(v.mac, [1,2,3,4,5,6]);
        assert_eq!(v.rx.size, 8);
        assert_eq!(v.tx.size, 8);
    }
}
